#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xc6c01fa, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x8d657ab9, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0x7d0571e5, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0x4203c482, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xdf64d62d, __VMLINUX_SYMBOL_STR(__dynamic_dev_dbg) },
	{ 0xfd75cb0, __VMLINUX_SYMBOL_STR(_dev_info) },
	{ 0x2c319a31, __VMLINUX_SYMBOL_STR(dev_notice) },
	{ 0x8ce73f94, __VMLINUX_SYMBOL_STR(pci_intx_mask_supported) },
	{ 0xc6cab830, __VMLINUX_SYMBOL_STR(__uio_register_device) },
	{ 0xf0ea8efd, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0xeb1f0daf, __VMLINUX_SYMBOL_STR(pci_enable_msix) },
	{ 0xa11b55b2, __VMLINUX_SYMBOL_STR(xen_start_info) },
	{ 0x731dba7a, __VMLINUX_SYMBOL_STR(xen_domain_type) },
	{ 0xbbd78bd4, __VMLINUX_SYMBOL_STR(dma_ops) },
	{ 0x2b9e8aac, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0x48254905, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0xf15e6c6b, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0x2c1c1039, __VMLINUX_SYMBOL_STR(pci_request_regions) },
	{ 0xb19de74, __VMLINUX_SYMBOL_STR(pci_enable_device) },
	{ 0x81fcd7c8, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x92a94ad2, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xa994264b, __VMLINUX_SYMBOL_STR(pci_check_and_mask_intx) },
	{ 0x88f2bfed, __VMLINUX_SYMBOL_STR(pci_intx) },
	{ 0xebc10668, __VMLINUX_SYMBOL_STR(pci_cfg_access_unlock) },
	{ 0xb51bda86, __VMLINUX_SYMBOL_STR(pci_cfg_access_lock) },
	{ 0x1ad4834e, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0x5944d015, __VMLINUX_SYMBOL_STR(__cachemode2pte_tbl) },
	{ 0xa50a80c2, __VMLINUX_SYMBOL_STR(boot_cpu_data) },
	{ 0xdd61dfc2, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xd17fbaf3, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0x323a933d, __VMLINUX_SYMBOL_STR(pci_release_regions) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0x25d0660, __VMLINUX_SYMBOL_STR(uio_unregister_device) },
	{ 0x9bc9fbf7, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x6534d1f2, __VMLINUX_SYMBOL_STR(pci_bus_type) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x7cc5449e, __VMLINUX_SYMBOL_STR(pci_enable_sriov) },
	{ 0xe328e548, __VMLINUX_SYMBOL_STR(pci_disable_sriov) },
	{ 0xca5c6963, __VMLINUX_SYMBOL_STR(pci_num_vf) },
	{ 0x3c80c06c, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio";


MODULE_INFO(srcversion, "AAF6B605BA43520608A3DD5");
