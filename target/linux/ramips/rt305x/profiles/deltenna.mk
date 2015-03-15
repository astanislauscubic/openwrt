#
# Copyright (C) 2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define Profile/WIBE4G
       NAME:=Deltenna WIBE4G
       PACKAGES:=kmod-switch-rtl8366s kmod-swconfig swconfig
endef

define Profile/WIBE4G/Description
       Package set for Deltenna WiBE 4G
endef

$(eval $(call Profile,WIBE4G))

