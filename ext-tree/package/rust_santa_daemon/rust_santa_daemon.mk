RUST_SANTA_DAEMON_VERSION = 1.0
RUST_SANTA_DAEMON_SITE = "$(BR2_EXTERNAL_SANTA_CLONE_PATH)/../src/rust_santa_daemon"
RUST_SANTA_DAEMON_SITE_METHOD = local

define RUST_SANTA_DAEMON_BUILD_CMDS
    cd $(@D) && $(TARGET_CONFIGURE_OPTS) $(PKG_CARGO_ENV) cargo build --release --manifest-path Cargo.toml --locked
endef

$(eval $(cargo-package))
