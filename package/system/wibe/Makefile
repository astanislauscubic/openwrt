# Deltenna WiBE support

include $(TOPDIR)/rules.mk

PKG_NAME:=wibe
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/wibe
  SECTION:=base
  CATEGORY:=Base system
  TITLE:=Deltenna WiBE
  URL:=http://www.deltenna.com
  VERSION:=$(PKG_RELEASE)-$(REVISION)
  DEPENDS:=+libjson-c
endef

define Package/wibe/conffiles
/etc/uci-defaults/00_password
/etc/uci-defaults/03_wifi
endef

define Package/wibe/description
 This package supports the Deltenna WiBE
endef

TARGET_CFLAGS += -I$(PKG_BUILD_DIR) \
                 -I$(STAGING_DIR)/usr/include \
                 -std=gnu99 \
                 -Wall -Werror -g
TARGET_CFLAGS += $(shell pkg-config --cflags json-c)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
	        CC=$(TARGET_CC) \
	        CFLAGS="$(TARGET_CFLAGS) $(BUILD_OPTS)" \
	        LDFLAGS="$(TARGET_LDFLAGS)" $(MAKEOPTS) \
	        LIBS="-luci -ljson-c"
endef

define Package/wibe/install
	mkdir -p $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/usr/sbin/

	$(CP) ./files/etc/uci-defaults/00_password $(1)/etc/uci-defaults/
	$(CP) ./files/etc/uci-defaults/03_wifi $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/umtsd $(1)/usr/sbin/umtsd
	$(STRIP) $(1)/usr/sbin/umtsd
endef

$(eval $(call BuildPackage,wibe))
