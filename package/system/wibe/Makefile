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
  DEPENDS:=+glib2 +libqmi +libuci
endef

PKG_CONFIG_DEPENDS=CONFIG_PACKAGE_glib2

define Package/wibe/conffiles
/etc/uci-defaults/00_password
/etc/uci-defaults/03_wifi
/etc/config/myproviders
/etc/config/iperf
endef

define Package/wibe/description
 This package supports the Deltenna WiBE
endef

export STAGING_PREFIX = $(STAGING_DIR)
TARGET_CFLAGS += -I$(PKG_BUILD_DIR) \
                 -I$(STAGING_DIR)/usr/include \
                 -std=gnu99 \
                 -Wall -Werror -g -Wno-deprecated-declarations
#TARGET_CFLAGS += $(shell $(PKG_CONFIG) --cflags json-c)
TARGET_CFLAGS += $(shell $(PKG_CONFIG) --cflags glib-2.0)
TARGET_CFLAGS += $(shell $(PKG_CONFIG) --cflags qmi-glib)
#TARGET_LIBS =    $(shell $(PKG_CONFIG) --libs json-c)
TARGET_LIBS +=   $(shell $(PKG_CONFIG) --libs glib-2.0)
TARGET_LIBS +=   $(shell $(PKG_CONFIG) --libs qmi-glib)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	STAGING_PREFIX=$(STAGING_DIR)/usr \
	$(MAKE) -C $(PKG_BUILD_DIR) \
	        CC=$(TARGET_CC) \
	        CFLAGS="$(TARGET_CFLAGS) $(BUILD_OPTS)" \
	        LDFLAGS="$(TARGET_LDFLAGS)" $(MAKEOPTS) \
	        LIBS="-luci $(TARGET_LIBS)"
endef

define Package/wibe/install
	mkdir -p $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/usr/share/umtsd/
	$(INSTALL_DIR) $(1)/lib/netifd/proto/

	$(CP) ./files/etc/init.d/umtsd $(1)/etc/init.d/umtsd
	$(CP) ./files/etc/init.d/iperf $(1)/etc/init.d/iperf
	$(CP) ./files/etc/init.d/wan_monitor $(1)/etc/init.d/wan_monitor
	$(CP) ./files/usr/share/umtsd/umtsd.sh $(1)/usr/share/umtsd/umtsd.sh
	$(CP) ./files/usr/share/umtsd/padding.bin $(1)/usr/share/umtsd/padding.bin
	$(CP) ./files/etc/uci-defaults/00_password $(1)/etc/uci-defaults/
	$(CP) ./files/etc/uci-defaults/03_wifi $(1)/etc/uci-defaults
	$(CP) ./files/etc/config/myproviders $(1)/etc/config/
	$(CP) ./files/etc/config/iperf $(1)/etc/config/
	$(CP) ./files/lib/netifd/proto/qmi.sh $(1)/lib/netifd/proto/
	$(CP) ./files/sbin/antenna_rescan $(1)/sbin/
	$(CP) ./files/sbin/antenna_reconnect $(1)/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/umtsd $(1)/sbin/umtsd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/download_data $(1)/usr/sbin/download_data
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wan_monitor $(1)/sbin/wan_monitor
	$(STRIP) $(1)/sbin/umtsd
	$(STRIP) $(1)/sbin/wan_monitor
	$(STRIP) $(1)/usr/sbin/download_data
endef

$(eval $(call BuildPackage,wibe))
