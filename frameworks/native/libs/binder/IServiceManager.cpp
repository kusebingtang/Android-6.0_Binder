/*
 * Copyright (C) 2005 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "ServiceManager"

#include <binder/IServiceManager.h>

#include <utils/Log.h>
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <utils/String8.h>
#include <utils/SystemClock.h>

#include <private/binder/Static.h>

#include <unistd.h>

namespace android {

/*
1. ProcessState::self()->getContextObject(NULL)、
   1. ProcessState::self()
      1. 打开驱动：binder
      2. 设置线程最大数目：15个
      3. mmap  -- 设置共享内存大小 --- （1M-8K） 普通服务的大小
   2. getContextObject
      1. 创建一个BpBinder --- 客户端的对象
2. interface_cast
   1. new BpServiceManager(new BpBinder) ==》 new Proxy(binder==BinderProxy)
   2. remote.transact -->远程调用  
   3. remote == BpBinder
   new BpServiceManager(new BpBinder(0))，在初始化过程中，
   比较重要工作的是类BpRefBase的mRemote指向new BpBinder(0)，从而BpServiceManager能够利用Binder进行通过通信。
3. java 层 --- ServiceManager.addService
   1. new ServiceManagerProxy(new BinderProxy)
   2. mRemote == BinderProxy
   3. BinderProxy.mObject == BpBinder
   4. mRemote.transact == BpBinder.transact
*/
sp<IServiceManager> defaultServiceManager()
{
    if (gDefaultServiceManager != NULL) return gDefaultServiceManager;
    {
        AutoMutex _l(gDefaultServiceManagerLock);//加锁
        while (gDefaultServiceManager == NULL) {
            //TODO-->interface_cast|new BpServiceManager(new BpBinder) ==》 new Proxy(binder==BinderProxy)
            gDefaultServiceManager = interface_cast<IServiceManager>(//interface_cast<IServiceManager>() 等价于 IServiceManager::asInterface()
                ProcessState::self()->getContextObject(NULL));
            if (gDefaultServiceManager == NULL)//如果没有初始化成功，sleep一秒，重新进入while
                sleep(1);
        }
    }
    
    return gDefaultServiceManager;
}

bool checkCallingPermission(const String16& permission)
{
    return checkCallingPermission(permission, NULL, NULL);
}

static String16 _permission("permission");


bool checkCallingPermission(const String16& permission, int32_t* outPid, int32_t* outUid)
{
    IPCThreadState* ipcState = IPCThreadState::self();
    pid_t pid = ipcState->getCallingPid();
    uid_t uid = ipcState->getCallingUid();
    if (outPid) *outPid = pid;
    if (outUid) *outUid = uid;
    return checkPermission(permission, pid, uid);
}

bool checkPermission(const String16& permission, pid_t pid, uid_t uid)
{
    sp<IPermissionController> pc;
    gDefaultServiceManagerLock.lock();
    pc = gPermissionController;
    gDefaultServiceManagerLock.unlock();
    
    int64_t startTime = 0;

    while (true) {
        if (pc != NULL) {
            bool res = pc->checkPermission(permission, pid, uid);
            if (res) {
                if (startTime != 0) {
                    ALOGI("Check passed after %d seconds for %s from uid=%d pid=%d",
                            (int)((uptimeMillis()-startTime)/1000),
                            String8(permission).string(), uid, pid);
                }
                return res;
            }
            
            // Is this a permission failure, or did the controller go away?
            if (IInterface::asBinder(pc)->isBinderAlive()) {
                ALOGW("Permission failure: %s from uid=%d pid=%d",
                        String8(permission).string(), uid, pid);
                return false;
            }
            
            // Object is dead!
            gDefaultServiceManagerLock.lock();
            if (gPermissionController == pc) {
                gPermissionController = NULL;
            }
            gDefaultServiceManagerLock.unlock();
        }
    
        // Need to retrieve the permission controller.
        sp<IBinder> binder = defaultServiceManager()->checkService(_permission);
        if (binder == NULL) {
            // Wait for the permission controller to come back...
            if (startTime == 0) {
                startTime = uptimeMillis();
                ALOGI("Waiting to check permission %s from uid=%d pid=%d",
                        String8(permission).string(), uid, pid);
            }
            sleep(1);
        } else {
            pc = interface_cast<IPermissionController>(binder);
            // Install the new permission controller, and try again.        
            gDefaultServiceManagerLock.lock();
            gPermissionController = pc;
            gDefaultServiceManagerLock.unlock();
        }
    }
}

// ----------------------------------------------------------------------

class BpServiceManager : public BpInterface<IServiceManager>
{
public:
    BpServiceManager(const sp<IBinder>& impl)
        : BpInterface<IServiceManager>(impl)//-->BpInterface
    {
    }

    virtual sp<IBinder> getService(const String16& name) const
    {
        unsigned n;
        for (n = 0; n < 5; n++){
            sp<IBinder> svc = checkService(name);
            if (svc != NULL) return svc;
            ALOGI("Waiting for service %s...\n", String8(name).string());
            sleep(1);
        }
        return NULL;
    }

    virtual sp<IBinder> checkService( const String16& name) const
    {
        Parcel data, reply;
        data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
        data.writeString16(name);
        remote()->transact(CHECK_SERVICE_TRANSACTION, data, &reply);//remote(BpBinder)
        return reply.readStrongBinder();
    }

    virtual status_t addService(const String16& name, const sp<IBinder>& service,
            bool allowIsolated)
    {
        Parcel data, reply; // Parcel 是内存共享读写
        data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());//写入地址// 写入头信息 "android.os.IServiceManager" ，ServiceManager 进程收到请求后会判断
        data.writeString16(name);//写入名字,例如-->"media.player"
        data.writeStrongBinder(service);// // MediaPlayerService 对象 
        data.writeInt32(allowIsolated ? 1 : 0);//默认false
        //-->[BpBinder::transact]
        status_t err = remote()->transact(ADD_SERVICE_TRANSACTION, data, &reply);//remote() 指向的是 BpBinder 对象
        return err == NO_ERROR ? reply.readExceptionCode() : err;
    }

    virtual Vector<String16> listServices()
    {
        Vector<String16> res;
        int n = 0;

        for (;;) {
            Parcel data, reply;
            data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
            data.writeInt32(n++);
            status_t err = remote()->transact(LIST_SERVICES_TRANSACTION, data, &reply);
            if (err != NO_ERROR)
                break;
            res.add(reply.readString16());
        }
        return res;
    }
};

IMPLEMENT_META_INTERFACE(ServiceManager, "android.os.IServiceManager");

// ----------------------------------------------------------------------

status_t BnServiceManager::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    //printf("ServiceManager received: "); data.print();
    switch(code) {
        case GET_SERVICE_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            String16 which = data.readString16();
            sp<IBinder> b = const_cast<BnServiceManager*>(this)->getService(which);
            reply->writeStrongBinder(b);
            return NO_ERROR;
        } break;
        case CHECK_SERVICE_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            String16 which = data.readString16();
            sp<IBinder> b = const_cast<BnServiceManager*>(this)->checkService(which);
            reply->writeStrongBinder(b);
            return NO_ERROR;
        } break;
        case ADD_SERVICE_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            String16 which = data.readString16();
            sp<IBinder> b = data.readStrongBinder();
            status_t err = addService(which, b);
            reply->writeInt32(err);
            return NO_ERROR;
        } break;
        case LIST_SERVICES_TRANSACTION: {
            CHECK_INTERFACE(IServiceManager, data, reply);
            Vector<String16> list = listServices();
            const size_t N = list.size();
            reply->writeInt32(N);
            for (size_t i=0; i<N; i++) {
                reply->writeString16(list[i]);
            }
            return NO_ERROR;
        } break;
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

}; // namespace android
