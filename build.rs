// Sojan James
// build.rs for cyclonedds-sys

/*
    Copyright 2020 Sojan James

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

use anyhow::Result;
use cc;
use once_cell::sync::Lazy;
use std::env;
use std::path::PathBuf;
use std::process::Command;

pub static OUT_DIR: Lazy<PathBuf> =
    Lazy::new(|| env::var_os("OUT_DIR").expect("OUT_DIR is not set").into());

fn main() {
    build::main();
}

macro_rules! log {
    ($fmt:expr) => (eprintln!(concat!("cyclonedds-sys/build.rs:{}: ", $fmt), line!()));
    ($fmt:expr, $($arg:tt)*) => (eprintln!(concat!("cyclonedds-sys/build.rs:{}: ", $fmt),
    line!(), $($arg)*));
}

mod build {

    extern crate bindgen;

    use std::env;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    //use walkdir::{DirEntry, WalkDir};
    use super::*;
    use anyhow::ensure;
    use glob::glob;

    static ENV_PREFIX: &str = "CYCLONEDDS";
    static LINKLIB: &str = "ddsc";
    static GIT_COMMIT: &str = "0e2cd3e303be2171dd0e4fc685cc5031f70b0f52";

    pub enum HeaderLocation {
        FromCMakeEnvironment(Vec<PathBuf>, PathBuf),
        FromYoctoSDKBuild(Vec<PathBuf>, PathBuf),
        FromEnvironment(Vec<PathBuf>),
        FromLocalBuild(Vec<PathBuf>),
    }

    impl HeaderLocation {
        fn add_paths(&mut self, mut path: Vec<PathBuf>) {
            match self {
                HeaderLocation::FromCMakeEnvironment(paths, _) => paths.append(&mut path),
                HeaderLocation::FromYoctoSDKBuild(paths, _) => paths.append(&mut path),
                HeaderLocation::FromEnvironment(paths) => paths.append(&mut path),
                HeaderLocation::FromLocalBuild(paths) => paths.append(&mut path),
            }
        }

        fn get_paths(&self) -> Vec<PathBuf> {
            match self {
                HeaderLocation::FromCMakeEnvironment(paths, _)
                | HeaderLocation::FromYoctoSDKBuild(paths, _)
                | HeaderLocation::FromEnvironment(paths)
                | HeaderLocation::FromLocalBuild(paths) => paths.clone(),
            }
        }
    }

    /// download cyclone dds from github
    fn download() -> Result<()> {
        // get head of master for now. We can change to a specific version when
        // needed

        let src_dir = OUT_DIR.join("cyclonedds");

        if !src_dir.exists() {
            log!("Cloning cyclonedds from github");

            let status = Command::new("git")
                .arg("clone")
                .arg("https://github.com/eclipse-cyclonedds/cyclonedds.git")
                .current_dir(&*OUT_DIR)
                .status()?;
            ensure!(status.success());
        }

        log!("Running git checkout");
        let status = Command::new("git")
            .arg("checkout")
            .arg(GIT_COMMIT)
            .current_dir(&src_dir)
            .status()?;
        ensure!(status.success());

        Ok(())
    }

    fn configure_and_build() -> Result<()> {
        let src_dir = OUT_DIR.join("cyclonedds");
        let build_dir = src_dir.join("build");
        let install_dir = src_dir.join("install");

        fs::create_dir_all(&build_dir)?;

        let status = Command::new("cmake")
            // .arg("-DBUILD_IDLC=OFF")
            .arg(format!("-DCMAKE_INSTALL_PREFIX={}", install_dir.display()))
            .arg("..")
            .current_dir(&build_dir)
            .status()?;
        ensure!(status.success());

        let status = Command::new("cmake")
            .arg("--build")
            .arg(".")
            .current_dir(&build_dir)
            .status()?;
        ensure!(status.success());

        let status = Command::new("cmake")
            .arg("--build")
            .arg(".")
            .arg("--target")
            .arg("install")
            .current_dir(&build_dir)
            .status()?;
        ensure!(status.success());

        Ok(())
    }

    fn find_iceoryx(iceoryx_version: &str) -> Option<HeaderLocation> {
        // Check if we are building with an OE SDK and the OECORE_TARGET_SYSROOT is set
        let iceoryx_header_path = format!(
            "usr/include/iceoryx/{}/iceoryx_binding_c/api.h",
            iceoryx_version
        );
        if let Some(sysroot) = env::var_os("OECORE_TARGET_SYSROOT") {
            let sysroot: PathBuf = sysroot.into();
            let header = sysroot.join(&iceoryx_header_path);
            if header.exists() {
                let iceoryx_include_path =
                    header.parent().unwrap().parent().unwrap().to_str().unwrap();
                let paths = vec![iceoryx_include_path.into()];
                //println!("cargo:warning=Found Iceoryx headers in OECORE_TARGET_SYSROOT");

                return Some(HeaderLocation::FromYoctoSDKBuild(paths, sysroot));
            }
        }

        // now look in local paths - nothing fancy here for now, just using the paths where iceoryx gets installed on my Ubuntu machine.
        let iceoryx_header_path = format!(
            "/usr/local/include/iceoryx/{}/iceoryx_binding_c/api.h",
            iceoryx_version
        );
        let header = PathBuf::from(&iceoryx_header_path);
        if header.exists() {
            //println!("cargo:warning=Found Iceoryx headers in {}",iceoryx_header_path);
            let iceoryx_include_path = header.parent().unwrap().parent().unwrap().to_str().unwrap();
            return Some(HeaderLocation::FromLocalBuild(vec![
                iceoryx_include_path.into()
            ]));
        }

        println!("cargo:warning=Iceoryx headers not found");
        None
    }

    fn find_cyclonedds() -> Option<HeaderLocation> {
        // The library name does not change. Print that out right away
        println!("cargo:rustc-link-lib={}", LINKLIB);

        // let outdir = env::var("OUT_DIR").expect("OUT_DIR is not set");

        // Check if we are building with an OE SDK and the OECORE_TARGET_SYSROOT is set
        if let Some(sysroot) = env::var_os("OECORE_TARGET_SYSROOT") {
            let sysroot: PathBuf = sysroot.into();
            let header = sysroot.join("usr/include/dds/dds.h");
            if header.exists() {
                let paths = vec![sysroot.clone()];
                println!("Found OECORE_TARGET_SYSROOT");
                return Some(HeaderLocation::FromYoctoSDKBuild(paths, sysroot));
            }
        }

        //first priority is environment variable.
        if let Ok(dir) = env::var(format!("{}_LIB_DIR", ENV_PREFIX)) {
            println!("cargo:rustc-link-search={}", dir);

            // Now find the include path
            if let Some(dir) = env::var_os(format!("{}_INCLUDE_DIR", ENV_PREFIX)) {
                let dir: PathBuf = dir.into();
                let path = dir.join("dds").join("dds.h");
                if path.exists() {
                    println!("Found {}", &path.to_str().unwrap());
                    let paths = vec![dir];
                    Some(HeaderLocation::FromEnvironment(paths))
                } else {
                    println!("Cannot find dds/dds.h");
                    None
                }
            } else {
                println!("LIB_DIR set but INCLUDE_DIR is unset");
                None
            }
        }
        // now check if building using CMAKE. CycloneDDS has a cmake
        // build environment. When building within CMake, the cyclonedds need not
        // be "installed", so multiple include paths are required.
        else if let Some(cmake_bin_dir) = env::var_os("CMAKE_BINARY_DIR") {
            let cmake_bin_dir: PathBuf = cmake_bin_dir.into();
            let lib_dir = cmake_bin_dir.join("lib");
            println!("cargo:rustc-link-search={}", lib_dir.display());

            if let Ok(dir) = env::var("CMAKE_SOURCE_DIR") {
                println!(
                    "CMAKE_SOURCE_DIR is set to {}, searching for include path",
                    &dir
                );
                let cmake_src_dir = Path::new(&dir);
                let glob_pattern = format!("{}/**/dds/dds.h", cmake_src_dir.display());
                println!("Glob pattern: {}", &glob_pattern);
                let mut paths = vec![];
                for entry in glob(&glob_pattern).expect("Glob pattern error") {
                    match entry {
                        Ok(path) => {
                            println!("{:?}", path.display());
                            let cyclone_src = path
                                .to_str()
                                .unwrap()
                                .split("cyclonedds")
                                .collect::<Vec<&str>>();
                            let mut cyclone_src = String::from(cyclone_src[0]);
                            cyclone_src.push_str("cyclonedds");
                            let cyclone_src = Path::new(&cyclone_src);

                            paths.push(cyclone_src.join("src/core/ddsc/include"));
                            paths.push(cyclone_src.join("src/core/include"));

                            //
                            paths.push(
                                find_cyclone_bin_dir(&cmake_bin_dir)
                                    .unwrap()
                                    .join("src/core/include"),
                            );

                            println!("{:?}", paths);
                            break;
                        }
                        Err(e) => println!("{:?}", e),
                    }
                }
                // now get the sysroot
                if let Some(toolchain_sysroot) = env::var_os("TOOLCHAIN_SYSROOT") {
                    Some(HeaderLocation::FromCMakeEnvironment(
                        paths,
                        toolchain_sysroot.into(),
                    ))
                } else {
                    println!("Unable to get TOOLCHAIN_SYSROOT");
                    Some(HeaderLocation::FromCMakeEnvironment(
                        paths,
                        PathBuf::from("/"),
                    ))
                }
            } else {
                None
            }
        } else {
            println!("No CMAKE environment or CYCLONEDDS_[LIB|INCLUDE]_DIR found");
            //try some defaults
            println!("cargo:rustc-link-search=/usr/local/lib");

            let path = format!("{}/dds/dds.h", "/usr/local/include");
            let path = Path::new(&path);
            if path.exists() {
                println!("Found {}", &path.to_str().unwrap());
                let paths = vec![PathBuf::from("/usr/local/include")];
                Some(HeaderLocation::FromEnvironment(paths))
            } else {
                println!("Cannot find dds/dds.h attempting to build");
                download().unwrap();
                configure_and_build().unwrap();

                let lib_dir = OUT_DIR.join("install").join("lib");
                let include_dir = OUT_DIR.join("install").join("include");
                let local_build_so = lib_dir.join("libddsc.so");

                if local_build_so.exists() {
                    println!("cargo:rustc-link-search={}", lib_dir.display());
                    let path = include_dir.join("dds").join("dds.h");

                    if path.exists() {
                        println!("Found {}", path.display());
                        let paths = vec![include_dir];
                        Some(HeaderLocation::FromLocalBuild(paths))
                    } else {
                        println!("Cannot find dds/dds.h");
                        None
                    }
                } else {
                    None
                }
            }
        }
    }

    fn find_cyclone_bin_dir(cmake_bin_dir: &Path) -> Option<PathBuf> {
        Some(cmake_bin_dir.join("sys/cyclonedds/src/ddsrt/include"))
    }

    fn add_whitelist(builder: bindgen::Builder) -> bindgen::Builder {
        builder
        .whitelist_function("dds_enable")
        .whitelist_function("dds_delete")
        .whitelist_function("dds_get_publisher")
        .whitelist_function("dds_get_subscriber")
        .whitelist_function("dds_get_datareader")
        .whitelist_function("dds_get_mask")
        .whitelist_function("dds_get_instance_handle")
        .whitelist_function("dds_read_status")
        .whitelist_function("dds_take_status")
        .whitelist_function("dds_get_status_changes")
        .whitelist_function("dds_get_status_mask")
        .whitelist_function("dds_get_enabled_status")
        .whitelist_function("dds_set_status_mask")
        .whitelist_function("dds_set_enabled_status")
        .whitelist_function("dds_get_qos")
        .whitelist_function("dds_set_qos")
        .whitelist_function("dds_get_listener")
        .whitelist_function("dds_set_listener")
        .whitelist_function("dds_read_status")
        .whitelist_function("dds_create_participant")
        .whitelist_function("dds_create_domain")
        .whitelist_function("dds_get_parent")
        .whitelist_function("dds_get_participant")
        .whitelist_function("dds_get_children")
        .whitelist_function("dds_get_domainid")
        .whitelist_function("dds_lookup_participant")
        .whitelist_function("dds_create_topic")
        .whitelist_function("dds_create_topic_arbitrary")
        .whitelist_function("dds_find_topic")
        .whitelist_function("dds_get_name")
        .whitelist_function("dds_get_type_name")
        .whitelist_function("dds_set_topic_filter")
        .whitelist_function("dds_get_topic_filter")
        .whitelist_function("dds_create_subscriber")
        .whitelist_function("dds_create_publisher")
        .whitelist_function("dds_suspend")
        .whitelist_function("dds_resume")
        .whitelist_function("dds_wait_for_acks")
        .whitelist_function("dds_create_reader")
        .whitelist_function("dds_create_reader_rhc")
        .whitelist_function("dds_reader_wait_for_historical_data")
        .whitelist_function("dds_create_writer")
        .whitelist_function("dds_register_instance")
        .whitelist_function("dds_unregister_instance")
        .whitelist_function("dds_unregister_instance_ih")
        .whitelist_function("dds_unregister_instance_ts")
        .whitelist_function("dds_unregister_instance_ih_ts")
        .whitelist_function("dds_writedispose")
        .whitelist_function("dds_writedispose_ts")
        .whitelist_function("dds_dispose")
        .whitelist_function("dds_dispose_ts")
        .whitelist_function("dds_dispose_ih")
        .whitelist_function("dds_dispose_ih_ts")
        .whitelist_function("dds_write")
        .whitelist_function("dds_write_flush")
        .whitelist_function("dds_writecdr")
        .whitelist_function("dds_write_ts")
        .whitelist_function("dds_create_readcondition")
        .whitelist_function("dds_create_querycondition")
        .whitelist_function("dds_create_guardcondition")
        .whitelist_function("dds_set_guardcondition")
        .whitelist_function("dds_read_guardcondition")
        .whitelist_function("dds_take_guardcondition")
        .whitelist_function("dds_create_waitset")
        .whitelist_function("dds_waitset_get_entities")
        .whitelist_function("dds_waitset_attach")
        .whitelist_function("dds_waitset_detach")
        .whitelist_function("dds_waitset_set_trigger")
        .whitelist_function("dds_waitset_wait")
        .whitelist_function("dds_waitset_wait_until")
        .whitelist_function("dds_read")
        .whitelist_function("dds_read_wl")
        .whitelist_function("dds_read_mask")
        .whitelist_function("dds_read_mask_wl")
        .whitelist_function("dds_read_instance")
        .whitelist_function("dds_read_instance_wl")
        .whitelist_function("dds_read_mask_wl")
        .whitelist_function("dds_read_instance_mask")
        .whitelist_function("dds_read_instance_mask_wl")
        .whitelist_function("dds_take")
        .whitelist_function("dds_take_wl")
        .whitelist_function("dds_take_mask")
        .whitelist_function("dds_take_mask_wl")
        .whitelist_function("dds_take_cdr")
        .whitelist_function("dds_take_instance")
        .whitelist_function("dds_take_instance_wl")
        .whitelist_function("dds_take_instance_mask")
        .whitelist_function("dds_take_instance_mask_wl")
        .whitelist_function("dds_take_next")
        .whitelist_function("dds_take_next_wl")
        .whitelist_function("dds_read_next")
        .whitelist_function("dds_read_next_wl")
        .whitelist_function("dds_return_loan")
        .whitelist_function("dds_lookup_instance")
        .whitelist_function("dds_instance_get_key")
        .whitelist_function("dds_begin_coherent")
        .whitelist_function("dds_end_coherent")
        .whitelist_function("dds_notify_readers")
        .whitelist_function("dds_triggered")
        .whitelist_function("dds_get_topic")
        .whitelist_function("dds_get_matched_subscriptions")
        .whitelist_function("dds_get_matched_subscription_data")
        .whitelist_function("dds_get_matched_publications")
        .whitelist_function("dds_get_matched_publication_data")
        .whitelist_function("dds_assert_liveliness")   /* DDS Public Listener API Follows */
        .whitelist_function("dds_create_listener")
        .whitelist_function("dds_delete_listener")
        .whitelist_function("dds_reset_listener")
        .whitelist_function("dds_copy_listener")
        .whitelist_function("dds_merge_listener")
        .whitelist_function("dds_lset_inconsistent_topic")
        .whitelist_function("dds_lset_liveliness_lost")
        .whitelist_function("dds_lset_offered_deadline_missed")
        .whitelist_function("dds_lset_offered_incompatible_qos")
        .whitelist_function("dds_lset_data_on_readers")
        .whitelist_function("dds_lset_sample_lost")
        .whitelist_function("dds_lset_data_available")
        .whitelist_function("dds_lset_sample_rejected")
        .whitelist_function("dds_lset_liveliness_changed")
        .whitelist_function("dds_lset_requested_deadline_missed")
        .whitelist_function("dds_lset_requested_incompatible_qos")
        .whitelist_function("dds_lset_offered_incompatible_qos")
        .whitelist_function("dds_lset_publication_matched")
        .whitelist_function("dds_lset_subscription_matched")
        .whitelist_function("dds_lget_inconsistent_topic")
        .whitelist_function("dds_lget_liveliness_lost")
        .whitelist_function("dds_lget_offered_deadline_missed")
        .whitelist_function("dds_lget_offered_incompatible_qos")
        .whitelist_function("dds_lget_data_on_readers")
        .whitelist_function("dds_lget_sample_lost")
        .whitelist_function("dds_lget_data_available")
        .whitelist_function("dds_lget_sample_rejected")
        .whitelist_function("dds_lget_liveliness_changed")
        .whitelist_function("dds_lget_requested_deadline_missed")
        .whitelist_function("dds_lget_requested_incompatible_qos")
        .whitelist_function("dds_lget_publication_matched")
        .whitelist_function("dds_lget_subscription_matched")  /* DDS Public Alloc APIs follow */
        .whitelist_function("dds_alloc")
        .whitelist_function("dds_realloc")
        .whitelist_function("dds_realloc_zero")
        .whitelist_function("dds_free")
        .whitelist_function("dds_string_alloc")
        .whitelist_function("dds_string_dup")
        .whitelist_function("dds_string_free")
        .whitelist_function("dds_sample_free")   /* DDS Public Status APIs follow */
        .whitelist_function("dds_get_inconsistent_topic_status")
        .whitelist_function("dds_get_publication_matched_status")
        .whitelist_function("dds_get_liveliness_lost_status")
        .whitelist_function("dds_get_offered_deadline_missed_status")
        .whitelist_function("dds_get_inconsistent_topic_status")
        .whitelist_function("dds_get_offered_incompatible_qos_status")
        .whitelist_function("dds_get_subscription_matched_status")
        .whitelist_function("dds_get_liveliness_changed_status")
        .whitelist_function("dds_get_sample_rejected_status")
        .whitelist_function("dds_get_sample_lost_status")
        .whitelist_function("dds_get_requested_deadline_missed_status")
        .whitelist_function("dds_get_requested_incompatible_qos_status")
        .whitelist_function("dds_get_inconsistent_topic_status")  /* DDS Public QOS APIs follow */
        .whitelist_function("dds_create_qos")
        .whitelist_function("dds_delete_qos")
        .whitelist_function("dds_reset_qos")
        .whitelist_function("dds_copy_qos")
        .whitelist_function("dds_merge_qos")
        .whitelist_function("dds_qos_equal")
        .whitelist_function("dds_qset_userdata")
        .whitelist_function("dds_qset_topicdata")
        .whitelist_function("dds_qset_groupdata")
        .whitelist_function("dds_qset_durability")
        .whitelist_function("dds_qset_history")
        .whitelist_function("dds_qset_resource_limits")
        .whitelist_function("dds_qset_presentation")
        .whitelist_function("dds_qset_lifespan")
        .whitelist_function("dds_qset_deadline")
        .whitelist_function("dds_qset_latency_budget")
        .whitelist_function("dds_qset_ownership")
        .whitelist_function("dds_qset_ownership_strength")
        .whitelist_function("dds_qset_liveliness")
        .whitelist_function("dds_qset_time_based_filter")
        .whitelist_function("dds_qset_partition")
        .whitelist_function("dds_qset_partition1")
        .whitelist_function("dds_qset_reliability")
        .whitelist_function("dds_qset_transport_priority")
        .whitelist_function("dds_qset_destination_order")
        .whitelist_function("dds_qset_writer_data_lifecycle")
        .whitelist_function("dds_qset_reader_data_lifecycle")
        .whitelist_function("dds_qset_durability_service")
        .whitelist_function("dds_qset_ignorelocal")
        .whitelist_function("dds_qget_userdata")
        .whitelist_function("dds_qget_topicdata")
        .whitelist_function("dds_qget_groupdata")
        .whitelist_function("dds_qget_durability")
        .whitelist_function("dds_qget_history")
        .whitelist_function("dds_qget_resource_limits")
        .whitelist_function("dds_qget_presentation")
        .whitelist_function("dds_qget_lifespan")
        .whitelist_function("dds_qget_deadline")
        .whitelist_function("dds_qget_latency_budget")
        .whitelist_function("dds_qget_ownership")
        .whitelist_function("dds_qget_ownership_strength")
        .whitelist_function("dds_qget_liveliness")
        .whitelist_function("dds_qget_time_based_filter")
        .whitelist_function("dds_qget_partition")
        .whitelist_function("dds_qget_reliability")
        .whitelist_function("dds_qget_transport_priority")
        .whitelist_function("dds_qget_destination_order")
        .whitelist_function("dds_qget_writer_data_lifecycle")
        .whitelist_function("dds_qget_reader_data_lifecyele")
        .whitelist_function("dds_qget_durability_service")
        .whitelist_function("dds_qget_history")
        .whitelist_function("dds_qget_ignorelocal")
        .whitelist_function("dds_qget_history")
        .whitelist_function("dds_create_topic_sertype")
        .whitelist_function("ddsi_sertype_init")
        .whitelist_function("ddsi_sertype_fini")
        .whitelist_function("ddsi_sertype_v0")
        .whitelist_function("ddsi_serdata_init")
        .whitelist_function("ddsi_serdata_addref")
        .whitelist_function("ddsi_serdata_removeref")
        .whitelist_function("ddsrt_md5_init")
        .whitelist_function("ddsrt_md5_append")
        .whitelist_function("ddsrt_md5_finish")
        .whitelist_function("iceoryx_header_from_chunk")
        .whitelist_function("shm_lock_iox_sub")
        .whitelist_function("shm_unlock_iox_sub")
        .whitelist_function("free_iox_chunk")
        .whitelist_function("shm_set_loglevel")
        .whitelist_function("shm_create_chunk")
        .whitelist_function("shm_set_data_state")
        .whitelist_function("shm_get_data_state")
        .whitelist_function("dds_is_loan_available")
        .whitelist_function("dds_is_shared_memory_available")
        .whitelist_function("dds_loan_shared_memory_buffer")
        .whitelist_function("dds_return_writer_loan")
        .whitelist_function("dds_loan_sample")
        .whitelist_function("_dummy")
        .whitelist_type("dds_stream_opcode")
        .whitelist_type("dds_stream_typecode")
        .whitelist_type("dds_stream_typecode_primary")
        .whitelist_type("dds_stream_typecode_subtype")
        .whitelist_type("dds_sequence_t")
        .whitelist_type("dds_duration_t")
        .whitelist_type("ddsi_sertype_ops")
        .whitelist_type("ddsi_serdata_ops")
        .whitelist_type("ddsi_sertype_init")
        .whitelist_type("nn_rdata")
        .whitelist_function("ddsrt_iovec_t")
        .whitelist_function("ddsrt_md5_state_t")
        .whitelist_var("DDS_DOMAIN_DEFAULT")
        .rustified_enum("dds_durability_kind")
        .rustified_enum("dds_history_kind")
        .rustified_enum("dds_ownership_kind")
        .rustified_enum("dds_liveliness_kind")
        .rustified_enum("dds_reliability_kind")
        .rustified_enum("dds_destination_order_kind")
        .rustified_enum("dds_presentation_access_scope_kind")
        .rustified_enum("dds_ignorelocal_kind")
        .whitelist_var("BUILTIN_TOPIC_DCPSPARTICIPANT")
        .whitelist_var("BUILTIN_TOPIC_DCPSTOPIC")
        .whitelist_var("BUILTIN_TOPIC_DCPSPUBLICATION")
        .whitelist_var("BUILTIN_TOPIC_DCPSSUBSCRIPTION")
 	.derive_default(true)
        .constified_enum("dds_status_id")
    }

    pub fn generate(include_paths: &Vec<PathBuf>, maybe_sysroot: Option<&PathBuf>) {
        let mut bindings = bindgen::Builder::default().header("wrapper.h");

        for path in include_paths {
            bindings = bindings.clang_arg(format!("-I{}", path.display()));
        }

        if let Some(sysroot) = maybe_sysroot {
            bindings = bindings.clang_arg(format!("--sysroot={}", sysroot.display()));
        }

        let gen = add_whitelist(bindings)
            .generate()
            .expect("Unable to generate bindings");

        if let Ok(path) = env::var("OUT_DIR") {
            let out_path = PathBuf::from(path);
            gen.write_to_file(out_path.join("bindings.rs"))
                .expect("Couldn't write bindings");
        } else {
            println!("OUT_DIR not set, not generating bindings");
        }
    }

    pub fn main() {
        for (key, value) in env::vars() {
            println!("{}: {}", key, value);
        }
        let mut headerloc = find_cyclonedds().unwrap();

        if let Some(iceoryx_headers) = find_iceoryx("v2.0.2") {
            headerloc.add_paths(iceoryx_headers.get_paths());
        } else if let Some(iceoryx_headers) = find_iceoryx("v2.0.0") {
            headerloc.add_paths(iceoryx_headers.get_paths());
        }

        match &headerloc {
            HeaderLocation::FromCMakeEnvironment(paths, sysroot) => generate(&paths, Some(sysroot)),
            HeaderLocation::FromEnvironment(paths) | HeaderLocation::FromLocalBuild(paths) => {
                generate(&paths, None)
            }
            HeaderLocation::FromYoctoSDKBuild(paths, sysroot) => generate(&paths, Some(sysroot)),
        }

        match &headerloc {
            HeaderLocation::FromCMakeEnvironment(paths, sysroot) => {
                compile_inlines(&paths, Some(sysroot))
            }
            HeaderLocation::FromEnvironment(paths) | HeaderLocation::FromLocalBuild(paths) => {
                compile_inlines(&paths, None)
            }
            HeaderLocation::FromYoctoSDKBuild(paths, sysroot) => {
                compile_inlines(&paths, Some(sysroot))
            }
        }
    }

    fn compile_inlines(include_paths: &Vec<PathBuf>, _maybe_sysroot: Option<&PathBuf>) {
        let mut cc = cc::Build::new();

        cc.file("inline_functions.c");

        for dir in include_paths {
            cc.include(dir);
        }
        cc.compile("libinline_functions.a");

        //if let Some(sysroot) = maybe_sysroot {
        //    cc.s
        //}
    }
}
