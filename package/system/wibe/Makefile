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
endef

define Package/wibe/conffiles
/etc/uci-defaults/00_password
/etc/uci-defaults/03_wifi
endef

define Package/wibe/description
 This package supports the Deltenna WiBE
endef

define Build/Prepare

endef

define Build/Compile

endef

define Package/wibe/install
	mkdir -p $(1)/etc/uci-defaults

	$(CP) ./files/etc/uci-defaults/00_password $(1)/etc/uci-defaults/
	$(CP) ./files/etc/uci-defaults/03_wifi $(1)/etc/uci-defaults
endef

$(eval $(call BuildPackage,wibe))
