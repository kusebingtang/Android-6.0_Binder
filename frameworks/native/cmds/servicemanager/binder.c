/* Copyright 2008 The Android Open Source Project
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "binder.h"

#define MAX_BIO_SIZE (1 << 30)

#define TRACE 0

#define LOG_TAG "Binder"
#include <cutils/log.h>

void bio_init_from_txn(struct binder_io *io, struct binder_transaction_data *txn);

#if TRACE
void hexdump(void *_data, size_t len)
{
    unsigned char *data = _data;
    size_t count;

    for (count = 0; count < len; count++) {
        if ((count & 15) == 0)
            fprintf(stderr,"%04zu:", count);
        fprintf(stderr," %02x %c", *data,
                (*data < 32) || (*data > 126) ? '.' : *data);
        data++;
        if ((count & 15) == 15)
            fprintf(stderr,"\n");
    }
    if ((count & 15) != 0)
        fprintf(stderr,"\n");
}

void binder_dump_txn(struct binder_transaction_data *txn)
{
    struct flat_binder_object *obj;
    binder_size_t *offs = (binder_size_t *)(uintptr_t)txn->data.ptr.offsets;
    size_t count = txn->offsets_size / sizeof(binder_size_t);

    fprintf(stderr,"  target %016"PRIx64"  cookie %016"PRIx64"  code %08x  flags %08x\n",
            (uint64_t)txn->target.ptr, (uint64_t)txn->cookie, txn->code, txn->flags);
    fprintf(stderr,"  pid %8d  uid %8d  data %"PRIu64"  offs %"PRIu64"\n",
            txn->sender_pid, txn->sender_euid, (uint64_t)txn->data_size, (uint64_t)txn->offsets_size);
    hexdump((void *)(uintptr_t)txn->data.ptr.buffer, txn->data_size);
    while (count--) {
        obj = (struct flat_binder_object *) (((char*)(uintptr_t)txn->data.ptr.buffer) + *offs++);
        fprintf(stderr,"  - type %08x  flags %08x  ptr %016"PRIx64"  cookie %016"PRIx64"\n",
                obj->type, obj->flags, (uint64_t)obj->binder, (uint64_t)obj->cookie);
    }
}

#define NAME(n) case n: return #n
const char *cmd_name(uint32_t cmd)
{
    switch(cmd) {
        NAME(BR_NOOP);
        NAME(BR_TRANSACTION_COMPLETE);
        NAME(BR_INCREFS);
        NAME(BR_ACQUIRE);
        NAME(BR_RELEASE);
        NAME(BR_DECREFS);
        NAME(BR_TRANSACTION);
        NAME(BR_REPLY);
        NAME(BR_FAILED_REPLY);
        NAME(BR_DEAD_REPLY);
        NAME(BR_DEAD_BINDER);
    default: return "???";
    }
}
#else
#define hexdump(a,b) do{} while (0)
#define binder_dump_txn(txn)  do{} while (0)
#endif

#define BIO_F_SHARED    0x01  /* needs to be buffer freed */
#define BIO_F_OVERFLOW  0x02  /* ran out of space */
#define BIO_F_IOERROR   0x04
#define BIO_F_MALLOCED  0x08  /* needs to be free()'d */

struct binder_state
{
    int fd;         // dev/binder的文件描述符
    void *mapped;   //指向mmap的内存地址
    size_t mapsize; //分配的内存大小，默认为128KB
};

/**
 * 先调用open()打开binder设备，open()方法经过系统调用，进入Binder驱动，然后调用方法binder_open()，
 * 该方法会在Binder驱动层创建一个binder_proc对象，再将binder_proc对象赋值给fd->private_data，
 * 同时放入全局链表binder_procs。再通过ioctl()检验当前binder版本与Binder驱动层的版本是否一致。
 * 
 * 调用mmap()进行内存映射，同理mmap()方法经过系统调用，对应于Binder驱动层的binder_mmap()方法，
 * 该方法会在Binder驱动层创建Binder_buffer对象，并放入当前binder_proc的proc->buffers链表。
*/
struct binder_state *binder_open(size_t mapsize)
{
    struct binder_state *bs;//-->[binder_state]
    struct binder_version vers;

    bs = malloc(sizeof(*bs));
    if (!bs) {
        errno = ENOMEM;
        return NULL;
    }

    bs->fd = open("/dev/binder", O_RDWR); //通过系统调用陷入内核，打开Binder设备驱动
    if (bs->fd < 0) {
        fprintf(stderr,"binder: cannot open device (%s)\n",
                strerror(errno));
        goto fail_open;// 无法打开binder设备
    }
    // 获取驱动版本，并判断版本是否一致
    if ((ioctl(bs->fd, BINDER_VERSION, &vers) == -1) ||
        (vers.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION)) {
        fprintf(stderr,
                "binder: kernel driver version (%d) differs from user space version (%d)\n",
                vers.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
        goto fail_open;//内核空间与用户空间的binder不是同一版本
    }

    bs->mapsize = mapsize; //  128k 字节大小的内存空间
    //通过系统调用，mmap内存映射，mmap必须是page的整数倍
    bs->mapped = mmap(NULL, mapsize, PROT_READ, MAP_PRIVATE, bs->fd, 0); // binder_mmap 内存映射
    if (bs->mapped == MAP_FAILED) {
        fprintf(stderr,"binder: cannot map device (%s)\n",
                strerror(errno));
        goto fail_map; // binder设备内存无法映射
    }

    return bs;

fail_map:
    close(bs->fd);
fail_open:
    free(bs);
    return NULL;
}

void binder_close(struct binder_state *bs)
{
    munmap(bs->mapped, bs->mapsize);
    close(bs->fd);
    free(bs);
}

// ServiceManager 进程：让 ServiceManager 进程成为管理者,整个系统中只有一个这样的管理者。 
int binder_become_context_manager(struct binder_state *bs)
{
    //通过ioctl，传递BINDER_SET_CONTEXT_MGR指令-->[binder_ioctl]
    return ioctl(bs->fd, BINDER_SET_CONTEXT_MGR, 0);//对应于Binder驱动层的binder_ioctl()方法.
}

int binder_write(struct binder_state *bs, void *data, size_t len)
{
    struct binder_write_read bwr;
    int res;

    bwr.write_size = len; // 代表写入数据大小，大小是 len
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) data; // 写入命令 BC_ENTER_LOOPER(此处data为BC_ENTER_LOOPER)
    bwr.read_size = 0; // read_size = 0，表示不读取数据
    bwr.read_consumed = 0;
    bwr.read_buffer = 0;
    //-->[binder_ioctl]
    res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);// 把 binder_write_read 写入 binder 驱动
    if (res < 0) {
        fprintf(stderr,"binder_write: ioctl failed (%s)\n",
                strerror(errno));
    }
    return res;
}

void binder_send_reply(struct binder_state *bs,
                       struct binder_io *reply,
                       binder_uintptr_t buffer_to_free,
                       int status)
{
    struct {
        uint32_t cmd_free;
        binder_uintptr_t buffer;
        uint32_t cmd_reply;
        struct binder_transaction_data txn;
    } __attribute__((packed)) data;

    data.cmd_free = BC_FREE_BUFFER;// free buffer命令
    data.buffer = buffer_to_free;
    data.cmd_reply = BC_REPLY;// reply命令
    data.txn.target.ptr = 0;
    data.txn.cookie = 0;
    data.txn.code = 0;
    if (status) {// status == 0
        data.txn.flags = TF_STATUS_CODE;
        data.txn.data_size = sizeof(int);
        data.txn.offsets_size = 0;
        data.txn.data.ptr.buffer = (uintptr_t)&status;
        data.txn.data.ptr.offsets = 0;
    } else {
        data.txn.flags = 0;
        data.txn.data_size = reply->data - reply->data0;
        data.txn.offsets_size = ((char*) reply->offs) - ((char*) reply->offs0);
        data.txn.data.ptr.buffer = (uintptr_t)reply->data0;
        data.txn.data.ptr.offsets = (uintptr_t)reply->offs0;
    }
    binder_write(bs, &data, sizeof(data)); // 向 Binder 驱动通信
}

// ptr 是读取数据的地址，是 bwr.read_buffer
int binder_parse(struct binder_state *bs, struct binder_io *bio,
                 uintptr_t ptr, size_t size, binder_handler func)
{
    int r = 1;
    uintptr_t end = ptr + (uintptr_t) size;

    while (ptr < end) {
        uint32_t cmd = *(uint32_t *) ptr;
        ptr += sizeof(uint32_t);
#if TRACE
        fprintf(stderr,"%s:\n", cmd_name(cmd));
#endif
        switch(cmd) {
        case BR_NOOP:// 无操作，退出循环
            break;
        case BR_TRANSACTION_COMPLETE:
            break;
        case BR_INCREFS:
        case BR_ACQUIRE:
        case BR_RELEASE:
        case BR_DECREFS:
#if TRACE
            fprintf(stderr,"  %p, %p\n", (void *)ptr, (void *)(ptr + sizeof(void *)));
#endif
            ptr += sizeof(struct binder_ptr_cookie);
            break;
        case BR_TRANSACTION: {//BINDER_WORK_TRANSACTION --- 要处理 cmd == BR_TRANSACTION
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: txn too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (func) {//-->回调函数
                unsigned rdata[256/4];
                struct binder_io msg;
                struct binder_io reply;//回写数据
                int res;
                //-->[bio_init]
                bio_init(&reply, rdata, sizeof(rdata), 4); // 创建回复的 reply-->reply初始化
                //-->[bio_init_from_txn]
                bio_init_from_txn(&msg, txn); // 从 txn 解析出 binder_io 信息
                //-->[service_manager|svcmgr_handler]
                res = func(bs, txn, &msg, &reply);// 调用解析回调函数 svcmgr_handler 
                //-->[binder_send_reply]
                binder_send_reply(bs, &reply, txn->data.ptr.buffer, res);  // 向binder驱动发送一个回复/将reply发给binder驱动
            }
            ptr += sizeof(*txn);
            break;
        }
        case BR_REPLY: {
            struct binder_transaction_data *txn = (struct binder_transaction_data *) ptr;
            if ((end - ptr) < sizeof(*txn)) {
                ALOGE("parse: reply too small!\n");
                return -1;
            }
            binder_dump_txn(txn);
            if (bio) {
                bio_init_from_txn(bio, txn);
                bio = 0;
            } else {
                /* todo FREE BUFFER */
            }
            ptr += sizeof(*txn);
            r = 0;
            break;
        }
        case BR_DEAD_BINDER: {
            struct binder_death *death = (struct binder_death *)(uintptr_t) *(binder_uintptr_t *)ptr;
            ptr += sizeof(binder_uintptr_t);
            //-->[ servicemanager/binder.c|binder_link_to_death]
            death->func(bs, death->ptr);// binder 死亡消息 
            break;
        }
        case BR_FAILED_REPLY:
            r = -1;
            break;
        case BR_DEAD_REPLY:
            r = -1;
            break;
        default:
            ALOGE("parse: OOPS %d\n", cmd);
            return -1;
        }
    }

    return r;
}

void binder_acquire(struct binder_state *bs, uint32_t target)
{
    uint32_t cmd[2];
    cmd[0] = BC_ACQUIRE;
    cmd[1] = target;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_release(struct binder_state *bs, uint32_t target)
{
    uint32_t cmd[2];
    cmd[0] = BC_RELEASE;
    cmd[1] = target;
    binder_write(bs, cmd, sizeof(cmd));
}

void binder_link_to_death(struct binder_state *bs, uint32_t target, struct binder_death *death)
{
    struct {
        uint32_t cmd;
        struct binder_handle_cookie payload;
    } __attribute__((packed)) data;

    data.cmd = BC_REQUEST_DEATH_NOTIFICATION;
    data.payload.handle = target;
    data.payload.cookie = (uintptr_t) death;
    binder_write(bs, &data, sizeof(data));//-->[binder_write]-->[binder_ioctl_write_read]
}

int binder_call(struct binder_state *bs,
                struct binder_io *msg, struct binder_io *reply,
                uint32_t target, uint32_t code)
{
    int res;
    struct binder_write_read bwr;
    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
    } __attribute__((packed)) writebuf;
    unsigned readbuf[32];

    if (msg->flags & BIO_F_OVERFLOW) {
        fprintf(stderr,"binder: txn buffer overflow\n");
        goto fail;
    }

    writebuf.cmd = BC_TRANSACTION;
    writebuf.txn.target.handle = target;
    writebuf.txn.code = code;
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = msg->data - msg->data0;
    writebuf.txn.offsets_size = ((char*) msg->offs) - ((char*) msg->offs0);
    writebuf.txn.data.ptr.buffer = (uintptr_t)msg->data0;
    writebuf.txn.data.ptr.offsets = (uintptr_t)msg->offs0;

    bwr.write_size = sizeof(writebuf);
    bwr.write_consumed = 0;
    bwr.write_buffer = (uintptr_t) &writebuf;

    hexdump(msg->data0, msg->data - msg->data0);
    for (;;) {
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
        bwr.read_buffer = (uintptr_t) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);

        if (res < 0) {
            fprintf(stderr,"binder: ioctl failed (%s)\n", strerror(errno));
            goto fail;
        }

        res = binder_parse(bs, reply, (uintptr_t) readbuf, bwr.read_consumed, 0);
        if (res == 0) return 0;
        if (res < 0) goto fail;
    }

fail:
    memset(reply, 0, sizeof(*reply));
    reply->flags |= BIO_F_IOERROR;
    return -1;
}

void binder_loop(struct binder_state *bs, binder_handler func)//由main()方法传递过来的参数func指向svcmgr_handler。
{
    int res;
    struct binder_write_read bwr;
    uint32_t readbuf[32];

    bwr.write_size = 0;
    bwr.write_consumed = 0;
    bwr.write_buffer = 0;
    // 将 BC_ENTER_LOOPER 写入驱动，告诉驱动当前进程进入循环
    readbuf[0] = BC_ENTER_LOOPER;
    //将BC_ENTER_LOOPER命令发送给binder驱动，让Service Manager进入循环-->[binder_write]
    binder_write(bs, readbuf, sizeof(uint32_t));

    // ServiceManager 进程：binder 线程进入循环等待，不断的读写 binder 内容
    for (;;) {//--》核心代码
        bwr.read_size = sizeof(readbuf);
        bwr.read_consumed = 0;
         // 不断的循环等待读取 binder 驱动的数据
        bwr.read_buffer = (uintptr_t) readbuf;

        res = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);//进入循环，不断地binder读写过程

        if (res < 0) {
            ALOGE("binder_loop: ioctl failed (%s)\n", strerror(errno));
            break;
        }
        // 解析远程进程的 binder 驱动信息-->对 getService请求进行解析-->[binder_parse]
        res = binder_parse(bs, 0, (uintptr_t) readbuf, bwr.read_consumed, func);
        if (res == 0) {
            ALOGE("binder_loop: unexpected reply?!\n");
            break;
        }
        if (res < 0) {
            ALOGE("binder_loop: io error %d %s\n", res, strerror(errno));
            break;
        }
    }
}
//将readbuf的数据赋给bio对象的data
void bio_init_from_txn(struct binder_io *bio, struct binder_transaction_data *txn)
{
    bio->data = bio->data0 = (char *)(intptr_t)txn->data.ptr.buffer;
    bio->offs = bio->offs0 = (binder_size_t *)(intptr_t)txn->data.ptr.offsets;
    bio->data_avail = txn->data_size;
    bio->offs_avail = txn->offsets_size / sizeof(size_t);
    bio->flags = BIO_F_SHARED;
}

void bio_init(struct binder_io *bio, void *data,
              size_t maxdata, size_t maxoffs)
{
    size_t n = maxoffs * sizeof(size_t);

    if (n > maxdata) {
        bio->flags = BIO_F_OVERFLOW;
        bio->data_avail = 0;
        bio->offs_avail = 0;
        return;
    }

    bio->data = bio->data0 = (char *) data + n;
    bio->offs = bio->offs0 = data;
    bio->data_avail = maxdata - n;
    bio->offs_avail = maxoffs;
    bio->flags = 0;
}

static void *bio_alloc(struct binder_io *bio, size_t size)
{
    size = (size + 3) & (~3);
    if (size > bio->data_avail) {
        bio->flags |= BIO_F_OVERFLOW;
        return NULL;
    } else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

void binder_done(struct binder_state *bs,
                 struct binder_io *msg,
                 struct binder_io *reply)
{
    struct {
        uint32_t cmd;
        uintptr_t buffer;
    } __attribute__((packed)) data;

    if (reply->flags & BIO_F_SHARED) {
        data.cmd = BC_FREE_BUFFER;
        data.buffer = (uintptr_t) reply->data0;
        binder_write(bs, &data, sizeof(data));
        reply->flags = 0;
    }
}

static struct flat_binder_object *bio_alloc_obj(struct binder_io *bio)
{
    struct flat_binder_object *obj;

    obj = bio_alloc(bio, sizeof(*obj));//-->[bio_alloc]

    if (obj && bio->offs_avail) {
        bio->offs_avail--;
        *bio->offs++ = ((char*) obj) - ((char*) bio->data0);
        return obj;
    }

    bio->flags |= BIO_F_OVERFLOW;
    return NULL;
}

void bio_put_uint32(struct binder_io *bio, uint32_t n)
{
    uint32_t *ptr = bio_alloc(bio, sizeof(n));
    if (ptr)
        *ptr = n;
}

void bio_put_obj(struct binder_io *bio, void *ptr)
{
    struct flat_binder_object *obj;

    obj = bio_alloc_obj(bio);
    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_BINDER;
    obj->binder = (uintptr_t)ptr;
    obj->cookie = 0;
}
//当找到服务的handle, 则调用bio_put_ref(reply, handle)，将handle封装到reply.
void bio_put_ref(struct binder_io *bio, uint32_t handle)
{
    struct flat_binder_object *obj;

    if (handle)
        obj = bio_alloc_obj(bio);//-->[bio_alloc_obj]
    else
        obj = bio_alloc(bio, sizeof(*obj));

    if (!obj)
        return;

    obj->flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    obj->type = BINDER_TYPE_HANDLE;//返回的是HANDLE类型
    obj->handle = handle;
    obj->cookie = 0;
}

void bio_put_string16(struct binder_io *bio, const uint16_t *str)
{
    size_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = 0;
    while (str[len]) len++;

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    bio_put_uint32(bio, (uint32_t) len);
    len = (len + 1) * sizeof(uint16_t);
    ptr = bio_alloc(bio, len);
    if (ptr)
        memcpy(ptr, str, len);
}

void bio_put_string16_x(struct binder_io *bio, const char *_str)
{
    unsigned char *str = (unsigned char*) _str;
    size_t len;
    uint16_t *ptr;

    if (!str) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    len = strlen(_str);

    if (len >= (MAX_BIO_SIZE / sizeof(uint16_t))) {
        bio_put_uint32(bio, 0xffffffff);
        return;
    }

    /* Note: The payload will carry 32bit size instead of size_t */
    bio_put_uint32(bio, len);
    ptr = bio_alloc(bio, (len + 1) * sizeof(uint16_t));
    if (!ptr)
        return;

    while (*str)
        *ptr++ = *str++;
    *ptr++ = 0;
}

static void *bio_get(struct binder_io *bio, size_t size)
{
    size = (size + 3) & (~3);

    if (bio->data_avail < size){
        bio->data_avail = 0;
        bio->flags |= BIO_F_OVERFLOW;
        return NULL;
    }  else {
        void *ptr = bio->data;
        bio->data += size;
        bio->data_avail -= size;
        return ptr;
    }
}

uint32_t bio_get_uint32(struct binder_io *bio)
{
    uint32_t *ptr = bio_get(bio, sizeof(*ptr));
    return ptr ? *ptr : 0;
}

uint16_t *bio_get_string16(struct binder_io *bio, size_t *sz)
{
    size_t len;

    /* Note: The payload will carry 32bit size instead of size_t */
    len = (size_t) bio_get_uint32(bio);
    if (sz)
        *sz = len;
    return bio_get(bio, (len + 1) * sizeof(uint16_t));
}

static struct flat_binder_object *_bio_get_obj(struct binder_io *bio)
{
    size_t n;
    size_t off = bio->data - bio->data0;

    /* TODO: be smarter about this? */
    for (n = 0; n < bio->offs_avail; n++) {
        if (bio->offs[n] == off)
            return bio_get(bio, sizeof(struct flat_binder_object));
    }

    bio->data_avail = 0;
    bio->flags |= BIO_F_OVERFLOW;
    return NULL;
}

uint32_t bio_get_ref(struct binder_io *bio)
{
    struct flat_binder_object *obj;

    obj = _bio_get_obj(bio);
    if (!obj)
        return 0;

    if (obj->type == BINDER_TYPE_HANDLE)
        return obj->handle;

    return 0;
}
