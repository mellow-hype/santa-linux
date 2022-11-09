SANTA_KMOD_VERSION = 1.0
SANTA_KMOD_SITE = "$(BR2_EXTERNAL_SANTA_CLONE_PATH)/../src/santa_kmod"
SANTA_KMOD_SITE_METHOD = local
$(eval $(kernel-module))
$(eval $(generic-package))
