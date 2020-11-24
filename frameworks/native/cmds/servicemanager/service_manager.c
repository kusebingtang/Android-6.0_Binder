/* Copyright 2008 The Android Open Source Project
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cutils/multiuser.h>

#include <private/android_filesystem_config.h>

#include <selinux/android.h>
#include <selinux/avc.h>

#include "binder.h"

#if 0
#define ALOGI(x...) fprintf(stderr, "svcmgr: " x)
#define ALOGE(x...) fprintf(stderr, "svcmgr: " x)
#else
#define LOG_TAG "ServiceManager"
#include <cutils/log.h>
#endif

const char *str8(const uint16_t *x, size_t x_len)
{
    static char buf[128];
    size_t max = 127;
    char *p = buf;

    if (x_len < max) {
        max = x_len;
    }

    if (x) {
        while ((max > 0) && (*x != '\0')) {
            *p++ = *x++;
            max--;
        }
    }
    *p++ = 0;
    return buf;
}

int str16eq(const uint16_t *a, const char *b)
{
    while (*a && *b)
        if (*a++ != *b++) return 0;
    if (*a || *b)
        return 0;
    return 1;
}

static int selinux_enabled;
static char *service_manager_context;
static struct selabel_handle* sehandle;

static bool check_mac_perms(pid_t spid, const char *tctx, const char *perm, const char *name)
{
    char *sctx = NULL;
    const char *class = "service_manager";
    bool allowed;

    if (getpidcon(spid, &sctx) < 0) {
        ALOGE("SELinux: getpidcon(pid=%d) failed to retrieve pid context.\n", spid);
        return false;
    }

    int result = selinux_check_access(sctx, tctx, class, perm, (void *) name);
    allowed = (result == 0);

    freecon(sctx);
    return allowed;
}

static bool check_mac_perms_from_getcon(pid_t spid, const char *perm)
{
    if (selinux_enabled <= 0) {
        return true;
    }

    return check_mac_perms(spid, service_manager_context, perm, NULL);
}

static bool check_mac_perms_from_lookup(pid_t spid, const char *perm, const char *name)
{
    bool allowed;
    char *tctx = NULL;

    if (selinux_enabled <= 0) {
        return true;
    }

    if (!sehandle) {
        ALOGE("SELinux: Failed to find sehandle. Aborting service_manager.\n");
        abort();
    }

    if (selabel_lookup(sehandle, &tctx, name, 0) != 0) {
        ALOGE("SELinux: No match for %s in service_contexts.\n", name);
        return false;
    }

    allowed = check_mac_perms(spid, tctx, perm, name);
    freecon(tctx);
    return allowed;
}

static int svc_can_register(const uint16_t *name, size_t name_len, pid_t spid, uid_t uid)
{
    const char *perm = "add";

    if (multiuser_get_app_id(uid) >= AID_APP) {
        return 0; /* Don't allow apps to register services */
    }

    return check_mac_perms_from_lookup(spid, perm, str8(name, name_len)) ? 1 : 0;
}

static int svc_can_list(pid_t spid)
{
    const char *perm = "list";
    return check_mac_perms_from_getcon(spid, perm) ? 1 : 0;
}

static int svc_can_find(const uint16_t *name, size_t name_len, pid_t spid)
{
    const char *perm = "find";
    return check_mac_perms_from_lookup(spid, perm, str8(name, name_len)) ? 1 : 0;
}

struct svcinfo
{
    struct svcinfo *next;
    uint32_t handle;
    struct binder_death death;
    int allow_isolated;
    size_t len;
    uint16_t name[0];
};

struct svcinfo *svclist = NULL;

struct svcinfo *find_svc(const uint16_t *s16, size_t len)
{
    struct svcinfo *si;

    for (si = svclist; si; si = si->next) {
        if ((len == si->len) &&
            !memcmp(s16, si->name, len * sizeof(uint16_t))) {
            return si;
        }
    }
    return NULL;
}

void svcinfo_death(struct binder_state *bs, void *ptr)
{
    struct svcinfo *si = (struct svcinfo* ) ptr;

    ALOGI("service '%s' died\n", str8(si->name, si->len));
    if (si->handle) {
        binder_release(bs, si->handle);
        si->handle = 0;
    }
}

uint16_t svcmgr_id[] = {
    'a','n','d','r','o','i','d','.','o','s','.',
    'I','S','e','r','v','i','c','e','M','a','n','a','g','e','r'
};


uint32_t do_find_service(struct binder_state *bs, const uint16_t *s, size_t len, uid_t uid, pid_t spid)
{
    struct svcinfo *si = find_svc(s, len);

    if (!si || !si->handle) {
        return 0;
    }

    if (!si->allow_isolated) {
        // If this service doesn't allow access from isolated processes,
        // then check the uid to see if it is isolated.
        uid_t appid = uid % AID_USER;
        if (appid >= AID_ISOLATED_START && appid <= AID_ISOLATED_END) {
            return 0;
        }
    }

    if (!svc_can_find(s, len, spid)) {
        return 0;
    }

    return si->handle;
}

int do_add_service(struct binder_state *bs,
                   const uint16_t *s, size_t len,
                   uint32_t handle, uid_t uid, int allow_isolated,
                   pid_t spid)
{
    struct svcinfo *si;

    //ALOGI("add_service('%s',%x,%s) uid=%d\n", str8(s, len), handle,
    //        allow_isolated ? "allow_isolated" : "!allow_isolated", uid);

    if (!handle || (len == 0) || (len > 127))//名字不能大于127个字符
        return -1;

    if (!svc_can_register(s, len, spid, uid)) { //权限检查 
        ALOGE("add_service('%s',%x) uid=%d - PERMISSION DENIED\n",
             str8(s, len), handle, uid);
        return -1;
    }

    si = find_svc(s, len); //服务检索 
    if (si) {
        if (si->handle) {
            ALOGE("add_service('%s',%x) uid=%d - ALREADY REGISTERED, OVERRIDE\n",
                 str8(s, len), handle, uid);
            svcinfo_death(bs, si);// 服务已注册时，释放之前添加的相应服务
        }
        si->handle = handle;// 重新放入新的
    } else {
        si = malloc(sizeof(*si) + (len + 1) * sizeof(uint16_t));
        if (!si) { // 内存不足，无法分配足够内存
            ALOGE("add_service('%s',%x) uid=%d - OUT OF MEMORY\n",
                 str8(s, len), handle, uid);
            return -1;
        }
        si->handle = handle; // 指定 handle 值
        si->len = len;
        memcpy(si->name, s, (len + 1) * sizeof(uint16_t));  // 指定当前添加服务的名称-->内存拷贝服务信息
        si->name[len] = '\0';
        si->death.func = (void*) svcinfo_death;
        si->death.ptr = si;
        si->allow_isolated = allow_isolated;
        si->next = svclist; // svclist保存所有已注册的服务
        svclist = si;
    }
    // 以 BC_ACQUIRE 命令，handle 为目标的信息，通过 ioctl 发送给 binder 驱动
    binder_acquire(bs, handle);//以 BC_ACQUIRE命令，handle为目标的信息，通过 ioctl发送给 binder驱动，binder_ref强引用 加 1操作
    // 以 BC_REQUEST_DEATH_NOTIFICATION 命令的信息，通过 ioctl 发送给 binder 驱动，主要用于清理内存等收尾工作
    binder_link_to_death(bs, handle, &si->death);
    return 0;
}

int svcmgr_handler(struct binder_state *bs,
                   struct binder_transaction_data *txn,
                   struct binder_io *msg,
                   struct binder_io *reply)
{
    struct svcinfo *si;//服务信息
    uint16_t *s;
    size_t len;
    uint32_t handle;
    uint32_t strict_policy;
    int allow_isolated;

    //ALOGI("target=%p code=%d pid=%d uid=%d\n",
    //      (void*) txn->target.ptr, txn->code, txn->sender_pid, txn->sender_euid);
    // 判断是不是要转给我的
    if (txn->target.ptr != BINDER_SERVICE_MANAGER)
        return -1;

    if (txn->code == PING_TRANSACTION)// PING_TRANSACTION，能不能找到我
        return 0;

    // Equivalent to Parcel::enforceInterface(), reading the RPC
    // header with the strict mode policy mask and the interface name.
    // Note that we ignore the strict_policy and don't propagate it
    // further (since we do no outbound RPCs anyway).
    strict_policy = bio_get_uint32(msg);
    s = bio_get_string16(msg, &len);
    if (s == NULL) {
        return -1;
    }

    if ((len != (sizeof(svcmgr_id) / 2)) ||
        memcmp(svcmgr_id, s, sizeof(svcmgr_id))) {
        fprintf(stderr,"invalid id %s\n", str8(s, len));
        return -1;
    }

    if (sehandle && selinux_status_updated() > 0) {//判断权限
        struct selabel_handle *tmp_sehandle = selinux_android_service_context_handle();
        if (tmp_sehandle) {
            selabel_close(sehandle);
            sehandle = tmp_sehandle;
        }
    }

    switch(txn->code) { // 判断 code 是什么命令
    case SVC_MGR_GET_SERVICE:// 查询获取 Service 服务命令
    case SVC_MGR_CHECK_SERVICE:
        s = bio_get_string16(msg, &len);// 要查询的服务名称
        if (s == NULL) {
            return -1;
        }
        handle = do_find_service(bs, s, len, txn->sender_euid, txn->sender_pid);// 从服务列表中寻找 handle 值
        if (!handle)
            break;
        bio_put_ref(reply, handle); // 把 handle 值写入回复数据
        return 0;

    case SVC_MGR_ADD_SERVICE:// 添加服务到列表
        s = bio_get_string16(msg, &len); // 获取服务的名称
        if (s == NULL) {
            return -1;
        }
        handle = bio_get_ref(msg); // 获取服务的 handle 的值
        allow_isolated = bio_get_uint32(msg) ? 1 : 0;
        if (do_add_service(bs, s, len, handle, txn->sender_euid, // 执行添加服务到列表的逻辑
            allow_isolated, txn->sender_pid))
            return -1;
        break;

    case SVC_MGR_LIST_SERVICES: {
        uint32_t n = bio_get_uint32(msg);

        if (!svc_can_list(txn->sender_pid)) {
            ALOGE("list_service() uid=%d - PERMISSION DENIED\n",
                    txn->sender_euid);
            return -1;
        }
        si = svclist;
        while ((n-- > 0) && si)
            si = si->next;
        if (si) {
            bio_put_string16(reply, si->name);
            return 0;
        }
        return -1;
    }
    default:
        ALOGE("unknown code %d\n", txn->code);
        return -1;
    }

    bio_put_uint32(reply, 0);
    return 0;
}


static int audit_callback(void *data, security_class_t cls, char *buf, size_t len)
{
    snprintf(buf, len, "service=%s", !data ? "NULL" : (char *)data);
    return 0;
}

/*
sm注册完成

1. 打开驱动，内存映射（设置大小 128K）
2. 设置 SM 为大管家 --- sm  作用  为了管理系统服务
   1. 创建 binder_node 结构体对象
   2. proc --》 binder_node
   3. 创建  work  和 todo --》类似 messageQueue
3. BC_ENTER_LOOPER 命令
   1. 写入状态Loop
   2. 去读数据：binder_thread_read：ret = wait_event_freezable_exclusive(proc->wait, binder_has_proc_work(proc, thread)); 进入等待
*/
int main(int argc, char **argv)
{
    struct binder_state *bs;

    bs = binder_open(128*1024); // 打开 binder 驱动，申请 128k 字节大小的内存空间 
    if (!bs) {
        ALOGE("failed to open binder driver\n");
        return -1;
    }

    if (binder_become_context_manager(bs)) {//注册成为 binder 服务的大管家：binder_become_context_manager；
        ALOGE("cannot become context manager (%s)\n", strerror(errno));
        return -1;
    }

    selinux_enabled = is_selinux_enabled();
    sehandle = selinux_android_service_context_handle();
    selinux_status_open(true);

    if (selinux_enabled > 0) {
        if (sehandle == NULL) {
            ALOGE("SELinux: Failed to acquire sehandle. Aborting.\n");
            abort();
        }

        if (getcon(&service_manager_context) != 0) {
            ALOGE("SELinux: Failed to acquire service_manager context. Aborting.\n");
            abort();
        }
    }

    union selinux_callback cb;
    cb.func_audit = audit_callback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);
    cb.func_log = selinux_log_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);

    binder_loop(bs, svcmgr_handler); // 进入无限循环，处理 client 端发来的请求 //svcmgr_handler-->回调

    return 0;
}
