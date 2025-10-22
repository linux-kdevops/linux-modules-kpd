/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef SMALL_STACK_SUPPORT_H
#define SMALL_STACK_SUPPORT_H

/* Allocate memory on heap */
#define __LC_DECLARE_MEM_HEAP(name, type, alignment)                           \
	type *name = kzalloc(round_up(sizeof(type), alignment), GFP_KERNEL);	\
	if (!name)                                                    \
		return -ENOMEM;                                                  \

#define __LC_RELEASE_MEM_HEAP(name)                                            \
	kfree_sensitive(name);

#define noinline_stack noinline

#define LC_DECLARE_MEM(name, type, alignment)                                  \
	_Pragma("GCC diagnostic push")                                         \
		_Pragma("GCC diagnostic ignored \"-Wcast-align\"")             \
			__LC_DECLARE_MEM_HEAP(name, type, alignment);          \
	_Pragma("GCC diagnostic pop")
#define LC_RELEASE_MEM(name) __LC_RELEASE_MEM_HEAP(name)

#endif /* SMALL_STACK_SUPPORT_H */
