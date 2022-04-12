// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "fishhook.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
    // malloc动态分配内存, 使用后判NULL, 因为动态分配内存可能会失败. malloc 返回void *指针, 可以转换为任意类型的指针
    struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
    if (!new_entry) {
        return -1;
    }
    new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    // 函数原型为void *memcpy(void *destin, void *source, unsigned n)；
    // 函数的功能是从源内存地址的起始位置开始拷贝若干个字节到目标内存地址中，即从源source中拷贝n个字节到目标destin中
    memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    new_entry->rebindings_nel = nel;
    // 将new_entry放入链表头
    new_entry->next = *rebindings_head;
    *rebindings_head = new_entry;
    return 0;
}

static vm_prot_t get_protection(void *sectionStart) {
    mach_port_t task = mach_task_self();
    vm_size_t size = 0;
    vm_address_t address = (vm_address_t)sectionStart;
    memory_object_name_t object;
#if __LP64__
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_region_basic_info_data_64_t info;
    kern_return_t info_ret = vm_region_64(
                                          task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)&info, &count, &object);
#else
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
    vm_region_basic_info_data_t info;
    kern_return_t info_ret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object);
#endif
    if (info_ret == KERN_SUCCESS) {
        return info.protection;
    } else {
        return VM_PROT_READ;
    }
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
    /*
     struct section_64 {
         char sectname[16];
         char segname[16];
         uint64_t addr;
         uint64_t size;
         uint32_t offset;
         uint32_t align;
         uint32_t reloff;
         uint32_t nreloc;
         uint32_t flags;
         uint32_t reserved1;
         uint32_t reserved2;
     };
     */
    
    /**
     步骤:
     nl_symbol_ptr 和 la_symbol_ptr 都是指针数组
     1. 由于nl_symbol_ptr和la_symbol_ptr section中的reserved1字段指明对应的indirect symbol table起始的index,
     找到indirect symbol table起始的index
     2. 遍历nl_symbol_ptr或la_symbol_ptr section(也就是动态符号表), 里面的值为动态符号在symbol table的下标
     3. 找到动态符号在symbol table的值, 然后获取strtab_offset, 其为String Table中的存储符号名称的偏移量
     4. 获取到符号名称, 进行对比
     5. 若符号名称相同, 则替换函数指针, 函数指针在 slide + section->addr [i] 处
     */
    
    // __nl_symbol_ptr为一个指针数组，直接对应non-lazy绑定数据。__la_symbol_ptr也是一个指针数组，通过dyld_stub_binder进行链接实现。
    // 对于 symbol pointer sections 和 stubs sections 来说，reserved1 表示 indirect table 数组的 index。用来索引 section's entries. stubs sections在__TEXT段的section
    
    // 这里找的是segment的segname为__DATA_CONST的section
    const bool isDataConst = strcmp(section->segname, SEG_DATA_CONST) == 0;
    // section为__got(__nl_symbol_ptr)或__la_symbnol_ptr
    // nl_symbol_ptr和la_symbol_ptr section中的reserved1字段指明对应的indirect symbol table起始的index
    // 其实在mach-o view中, 已经标明出来了, reserved1就是Indirect Sym Index
    /**
     Mach-O File Format Reference 中这样说明的:
     reserved1
     An integer reserved for use with certain section types. For symbol pointer sections and symbol stubs
     sections that refer to indirectsymbol table entries, this is the index into the indirect table for this section’s entries. The number of entries is based on the section size divided by the size of the symbol pointer or stub. Otherwise, this field is set to 0.
     */
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    // slide+section->addr 就是符号对应的存放函数实现的数组, 也就是相应的__nl_symbol_ptr和__la_symbol_ptr, 函数指针都在这里面
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    vm_prot_t oldProtection = VM_PROT_READ;
    if (isDataConst) {
        oldProtection = get_protection(rebindings);
        mprotect(indirect_symbol_bindings, section->size, PROT_READ | PROT_WRITE);
    }
    // 遍历nl_symbol_ptr 或 la_symbol_ptr section里面的每一个符号
    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        // 找到符号在Indrect Symbol Table表中的值
        // 读取indirect table中的数据
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        // 以symtab_index作为下标，访问symbol table
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        // 获取到symbol_name
        char *symbol_name = strtab + strtab_offset;
        // 判断函数的名称是否有两个字符，为啥是两个，因为函数前面有个_，所以方法的名称最少要1个
        bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
        // 遍历最初的链表，来进行hook
        struct rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                // 这里if的条件就是判断从symbol_name[1]两个函数的名字是否都是一致的，以及判断两个
                if (symbol_name_longer_than_1 &&
                    strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    // 判断replaced的地址不为NULL以及我方法的实现和rebindings[j].replacement的方法不一致
                    if (cur->rebindings[j].replaced != NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        // 让rebindings[j].replaced保存indirect_symbol_bindings[i]的函数地址
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    // 将替换后的方法给原先的方法，也就是替换内容为自定义函数地址
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto symbol_loop;
                }
            }
            cur = cur->next;
        }
    symbol_loop:;
    }
    if (isDataConst) {
        int protection = 0;
        if (oldProtection & VM_PROT_READ) {
            protection |= PROT_READ;
        }
        if (oldProtection & VM_PROT_WRITE) {
            protection |= PROT_WRITE;
        }
        if (oldProtection & VM_PROT_EXECUTE) {
            protection |= PROT_EXEC;
        }
        mprotect(indirect_symbol_bindings, section->size, protection);
    }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
    /**
     dladdr(): 将地址翻译成符号信息
     文档:http://www.qnx.com/developers/docs/qnxcar2/index.jsp?topic=%2Fcom.qnx.doc.neutrino.lib_ref%2Ftopic%2Fd%2Fdladdr.html
     应用:https://www.dazhuanlan.com/2019/12/07/5deb029c65d6e/
     Dl_info是一个结构, 可以在其中存储符号信息:
     struct {
         const char *dli_fname;　　// 库的路径
         void *dli_fbase;          // 基址
         const char *dli_sname;     // 符号名称
         void *dli_saddr;           // 符号地址
         size_t dli_size; // ELF only
         int dli_bind; // ELF only
         int dli_type;
     };
     */
    Dl_info info;
    if (dladdr(header, &info) == 0) {
        return;
    }
    
    // 可以参考OS X ABI Mach-O File Format Reference
    // LINKEDIT段包含动态链接器使用的原始数据，例如符号、字符串和重定位表条目（symbol, string, and relocation table entries）
    // load_command LC_SYMTAB和LC_DYSYMTAB 描述了符号表的大小和位置以及其他元数据
    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    struct symtab_command* symtab_cmd = NULL;
    struct dysymtab_command* dysymtab_cmd = NULL;
    
    // 要去寻找load command，所以这里跳过sizeof(mach_header_t)大小, mach header后面是load command
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);

//     struct mach_header_64 {
//         uint32_t    magic;        /* mach magic number identifier */
//         cpu_type_t    cputype;    /* cpu specifier */
//         cpu_subtype_t    cpusubtype;    /* machine specifier */
//         uint32_t    filetype;    /* type of file */
//         uint32_t    ncmds;        /* number of load commands */
//         uint32_t    sizeofcmds;    /* the size of all the load commands */
//         uint32_t    flags;        /* flags */
//         uint32_t    reserved;    /* reserved */
//     };
//    struct load_command {
//        uint32_t cmd;        /* type of load command */
//        uint32_t cmdsize;    /* total size of command in bytes */
//    };
//        struct segment_command
//        {
//            uint32_t cmd;
//            uint32_t cmdsize;
//            char segname[16];
//            uint32_t vmaddr;
//            uint32_t vmsize;
//            uint32_t fileoff;
//            uint32_t filesize;
//            vm_prot_t maxprot;
//            vm_prot_t initprot;
//            uint32_t nsects;
//            uint32_t flags;
//        };
    
    /**
     步骤:
     1. 找到Load Commands
     2. 然后遍历Load Commands, 找到:
        (1)__LINKEDIT的Load Command
        (2)Symbol Table的Load Command(LC_SYMTAB)
        (3)Dynamic Symbol Table的Load Command(LC_DYSYMTAB)
     3. 找出__LINKEDIT段的基址, __LINKEDIT段包含了Symbol Table和Dynamic Symbol Table 以及 String Table
     4. 进而找出Symbol Table和Dynamic Symbol Table 以及 String Table的地址
     5. 重新遍历Load Commands, 找到__la_symbol_ptr和__nl_symbol_ptr
     */
    
    // 遍历每一个 Load Command，游标每一次偏移每个命令的Command Size 大小
    // header -> ncmds: Load Command 数量
    // cur_seg_cmd -> cmdsize: Load Command 大小
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        // 取出当前的 Load Command
        cur_seg_cmd = (segment_command_t *)cur;
        
        /**
        LC_SEGMENT segment_command 定义要映射到进程的地址空间中的这个文件的sgement。
        它还包括该sgement所包含的所有section。
         */
        // cmd为一个整数, 表明load command的类型
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            // 判断是否为__LINKEDIT段的load command, 也就是说, LINKEDIT load command的类型是LC_SEGMENT
            // __LINKEDIT，其中包含需要被动态链接器使用的信息，包括符号表、字符串表、重定位项表、签名等
            // 观察Mach-O View, 由__LINKEDIT的file offset可以得到__LINKEDIT内容的位置, 其正好在Section之后, file offset + file size 发现位置正好在Mach-O文件最后, 包含Dynamic Loader Info/Function Starts/Symbol Table/Data in Code Entries/Dynamic Symbol Table/String Table/Code Signature
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            /*
             LC_SYMTAB指定此文件的符号表。静态和动态链接器在链接文件时都会使用此信息，调试器也会使用此信息将符号映射到生成符号的原始源代码文件。

             LC_SYMTAB这个LoadCommand主要提供了两个信息
             Symbol Table的偏移量与Symbol Table中元素的个数
             String Table的偏移量与String Table的长度
             
             疑问: Symbol Table 这个是在__LINKEDIT中的, 为何又要使用LC_SYMTAB在记录一遍
             解答: 目前来看__LINKEDIT是一个总的segment, 里面包含了Symbol Table等
             */
            symtab_cmd = (struct symtab_command*)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            /**
             LC_DYSYMTAB指定动态链接器使用的其他符号表信息Dynamic Symbol Table。
             
             LC_DYSYMTAB
             提供了动态符号表的位移和元素个数，还有一些其他的表格索引
             */
            dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
        }
    }
    
    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
        !dysymtab_cmd->nindirectsyms) {
        return;
    }
    
    // Find base symbol/string table addresses
    /**
     链接时linkedit的基址 = __LINKEDIT.VM_Address - __LINKEDIT.File_Offset + silde
     silde由ASLR生成, Address space layout randomization，将可执行程序随机装载到内存中,这里的随机只是偏移，
     而不是打乱，具体做法就是通过内核将 Mach-O的段“平移”某个随机系数。slide 正是ASLR引入的偏移，也就是说linkedit的基址等于__LINKEDIT的地址减去文件偏移量，然后再加上ASLR造成的偏移
     */
    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    // 符号表的地址 = 基址 + 符号表偏移量
    // 通过 base + symtab 的偏移量 计算 symtab 表的首地址，并获取 nlist_t 结构体实例
    nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    // 字符串表的地址 = 基址 + 字符串表偏移量
    // 通过 base + stroff 字符表偏移量计算字符表中的首地址，获取字符串表
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    
    // Get indirect symbol table (array of uint32_t indices into symbol table)
    // 动态符号表地址 = 基址 + 动态符号表偏移量
    // 通过 base + indirectsymoff 偏移量来计算动态符号表的首地址
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
     
    // 重新回到load commands起始位置
    cur = (uintptr_t)header + sizeof(mach_header_t);
    // 再次遍历 Load Commands
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            // 寻找segname为__DATA和__DATA_CONST的segment
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
                continue;
            }
            // nsects标示了segment中有多少secetion
            for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
                // 这里寻找的是 Section Header
                // 疑问? 但是这个计算方式看不懂
                section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
                // 寻找__la_symbol_ptr
                // flags & SECTION_TYPE 通过 SECTION_TYPE 掩码获取 flags 记录类型的 8 bit
                // 如果 section 的类型为 S_LAZY_SYMBOL_POINTERS
                // 这个类型代表 lazy symbol 指针 Section
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                    // 进行 rebinding 重写操作
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
                // 寻找__nl_symbol_ptr, 在mach-o view中section header 为__got
                // 这个类型代表 non-lazy symbol 指针 Section
                if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
            }
        }
    }
}

// 参数1: mach_header的地址
// 参数2: 由于ASLR(地址随机分布), 导致程序实际的虚拟内存地址与mach-o结构中的地址不一致, 需要一个偏移量slide, slide是随机生成的
static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
    struct rebindings_entry *rebindings_head = NULL;
    int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
    rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
    if (rebindings_head) {
        free(rebindings_head->rebindings);
    }
    free(rebindings_head);
    return retval;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
    int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
    if (retval < 0) {
        return retval;
    }
    // If this was the first call, register callback for image additions (which is also invoked for
    // existing images, otherwise, just run on existing images
    // 注册image回调, 已经注册的会立马调用, 没有注册的会在添加时调用
    
    // 直接使用不也可以么 dyld_register_func_for_add_image
    if (!_rebindings_head->next) {
        // 第一次调用fishhook
        // _dyld_register_func_for_add_image 注册自定义回调
        _dyld_register_func_for_add_image(_rebind_symbols_for_image);
    } else {
        // 非首次调用则遍历已存在的所有镜像(image)，手动执行自定义回调方法
        // 疑惑??? 为什么不都用dyld_register_func_for_add_image呢
        // 解答: 因为要立即生效, 没有添加的image可以通过dyld_register_func_for_add_image进行回调
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
    return retval;
}
