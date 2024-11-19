// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the code to register digest list parsers.
 */

#define pr_fmt(fmt) "digest_cache: "fmt
#include <linux/init_task.h>
#include <linux/namei.h>
#include <uapi/linux/module.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>

#include "internal.h"

static DEFINE_MUTEX(parsers_mutex);
static LIST_HEAD(parsers);

/**
 * load_parser - Load kernel module containing a parser
 * @dentry: Dentry of the inode for which the digest cache will be used
 * @digest_cache: Digest cache
 * @name: Name of the parser to load
 *
 * This function opens a kernel module file in
 * /lib/modules/<kernel ver>/security/integrity/digest_cache, and executes
 * ksys_finit_module() to load the kernel module. After kernel module
 * initialization, the parser should be found in the linked list of parsers.
 *
 * Return: Zero if kernel module is loaded, a POSIX error code otherwise.
 */
static int load_parser(struct dentry *dentry, struct digest_cache *digest_cache,
		       const char *name)
{
	char *compress_suffix = "";
	char *parser_path;
	struct file *file;
	struct path path;
	int ret = 0, flags = 0;

	/* Must be kept in sync with kernel/module/Kconfig. */
	if (IS_ENABLED(CONFIG_MODULE_COMPRESS_GZIP))
		compress_suffix = ".gz";
	else if (IS_ENABLED(CONFIG_MODULE_COMPRESS_XZ))
		compress_suffix = ".xz";
	else if (IS_ENABLED(CONFIG_MODULE_COMPRESS_ZSTD))
		compress_suffix = ".zst";

	if (strlen(compress_suffix))
		flags |= MODULE_INIT_COMPRESSED_FILE;

	parser_path = kasprintf(GFP_KERNEL, "%s/%s.ko%s", PARSERS_DIR, name,
				compress_suffix);
	if (!parser_path)
		return -ENOMEM;

	ret = kern_path(parser_path, 0, &path);
	if (ret < 0) {
		pr_debug("Cannot find path %s\n", parser_path);
		goto out;
	}

	/* Cannot request a digest cache for the kernel module inode. */
	if (d_backing_inode(dentry) == d_backing_inode(path.dentry)) {
		pr_debug("Cannot request a digest cache for kernel module %s\n",
			 dentry->d_name.name);
		ret = -EBUSY;
		goto out;
	}

	file = kernel_file_open(&path, O_RDONLY, &init_cred);
	if (IS_ERR(file)) {
		pr_debug("Cannot open %s\n", parser_path);
		ret = PTR_ERR(file);
		goto out_path;
	}

	/* Mark the file descriptor as ours. */
	digest_cache_to_file_sec(file, digest_cache);

	ret = ksys_finit_module(file, "", flags);
	if (ret < 0)
		pr_debug("Cannot load module %s\n", parser_path);

	fput(file);
out_path:
	path_put(&path);
out:
	kfree(parser_path);
	return ret;
}

/**
 * lookup_get_parser - Lookup and get parser among registered ones
 * @name: Name of the parser to search
 *
 * This function searches a parser among the registered ones, and returns it
 * to the caller, after incrementing the kernel module reference count.
 *
 * Must be called with parser_mutex held.
 *
 * Return: A parser structure if parser is found and available, NULL otherwise.
 */
static struct parser *lookup_get_parser(const char *name)
{
	struct parser *entry, *found = NULL;

	list_for_each_entry(entry, &parsers, list) {
		if (!strcmp(entry->name, name) &&
		    try_module_get(entry->owner)) {
			found = entry;
			break;
		}
	}

	return found;
}

/**
 * put_parser - Put parser
 * @parser: Parser to put
 *
 * This function decreases the kernel module reference count.
 */
static void put_parser(struct parser *parser)
{
	module_put(parser->owner);
}

/**
 * digest_cache_parse_digest_list - Parse a digest list
 * @dentry: Dentry of the inode for which the digest cache will be used
 * @digest_cache: Digest cache
 * @path_str: Path string of the digest list
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function selects a parser for a digest list depending on its file name,
 * and calls the appropriate parsing function. It expects the file name to be
 * in the format: [<seq num>-]<digest list format>-<digest list name>.
 * <seq num>- is optional.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_parse_digest_list(struct dentry *dentry,
				   struct digest_cache *digest_cache,
				   char *path_str, void *data, size_t data_len)
{
	char *filename, *format, *next_sep;
	struct parser *parser;
	char format_buf[sizeof(parser->name)];
	int ret = -EINVAL;

	filename = strrchr(path_str, '/');
	if (!filename)
		return ret;

	filename++;
	format = filename;

	/*
	 * Since we expect that all files start with a digest list format, this
	 * check is reliable to detect <seq num>.
	 */
	if (filename[0] >= '0' && filename[0] <= '9') {
		format = strchr(filename, '-');
		if (!format)
			return ret;

		format++;
	}

	next_sep = strchr(format, '-');
	if (!next_sep || next_sep - format >= sizeof(format_buf))
		return ret;

	snprintf(format_buf, sizeof(format_buf), "%.*s",
		 (int)(next_sep - format), format);

	pr_debug("Parsing %s, format: %s, size: %ld\n", path_str, format_buf,
		 data_len);

	mutex_lock(&parsers_mutex);
	parser = lookup_get_parser(format_buf);
	mutex_unlock(&parsers_mutex);

	if (!parser) {
		load_parser(dentry, digest_cache, format_buf);

		mutex_lock(&parsers_mutex);
		parser = lookup_get_parser(format_buf);
		mutex_unlock(&parsers_mutex);

		if (!parser) {
			pr_debug("Digest list parser %s not found\n",
				 format_buf);
			return -ENOENT;
		}
	}

	ret = parser->func(digest_cache, data, data_len);
	put_parser(parser);

	return ret;
}

/**
 * digest_cache_register_parser - Register new parser
 * @parser: Parser structure to register
 *
 * This function searches the parser name among the registered ones and, if not
 * found, appends the parser to the linked list of parsers.
 *
 * Return: Zero on success, -EEXIST if a parser with the same name exists.
 */
int digest_cache_register_parser(struct parser *parser)
{
	struct parser *p;
	int ret = 0;

	mutex_lock(&parsers_mutex);
	p = lookup_get_parser(parser->name);
	if (p) {
		put_parser(p);
		ret = -EEXIST;
		goto out;
	}

	list_add_tail(&parser->list, &parsers);
out:
	pr_debug("Digest list parser \'%s\' %s registered\n", parser->name,
		 (ret < 0) ? "cannot be" : "successfully");

	mutex_unlock(&parsers_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(digest_cache_register_parser);

/**
 * digest_cache_unregister_parser - Unregister parser
 * @parser: Parser structure to unregister
 *
 * This function removes the passed parser from the linked list of parsers.
 */
void digest_cache_unregister_parser(struct parser *parser)
{
	mutex_lock(&parsers_mutex);
	list_del(&parser->list);
	mutex_unlock(&parsers_mutex);

	pr_debug("Digest list parser \'%s\' successfully unregistered\n",
		 parser->name);
}
EXPORT_SYMBOL_GPL(digest_cache_unregister_parser);
