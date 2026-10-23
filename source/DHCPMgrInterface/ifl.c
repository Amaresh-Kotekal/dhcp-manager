/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2020 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
************************************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>

#define gettid() syscall(SYS_gettid)

#include "errno.h"
#include "sysevent/sysevent.h"
#include "safec_lib_common.h"
#include "ifl_priv.h"
#include "ifl_queue_impl.h"
#include "ifl_thread.h"

#define LOCALHOST   "127.0.0.1"

typedef struct _thread_data_t {
    void*               qObj;
    uint8               ctxID;
} thread_data_t;

typedef struct _q_data_t {
    fptr_t              cb;
    char                eValue[BUFLEN_64];
} q_data_t;

typedef struct _handler_t {
    fptr_t              cb;
    uint8               ctxID;
    ifl_event_type   eType;
} handler_t;

typedef struct _event_handler_map_t {
    char                event[BUFLEN_64];
    handler_t           handler[IFL_MAX_CONTEXT];
    uint8               handlerCount;
    async_id_t          asyncID;
} event_handler_map_t;

typedef struct _q_context_idx_map_t {
    char                qCtx[BUFLEN_16];
    void*               qObj;
} q_context_idx_map_t;

typedef struct _task_resource_t {
    int                 se_fd;
    token_t             se_tok;
} task_resource_t;

typedef struct _task_resource_table_t {
    pid_t               tID;
    char                tCtx[BUFLEN_16];
    task_resource_t*    tResrc;
} task_resource_table_t;


/*
 * static globals
 */
static event_handler_map_t    evtToHdlMap[IFL_MAX_EVENT_HANDLER_MAP];
static q_context_idx_map_t    ctxToIdxMap[IFL_MAX_CONTEXT];
static uint8                  thdToIdxMap[IFL_MAX_CONTEXT];
static task_resource_table_t  tskResrcTbl[IFL_MAX_TASK_RESOURCE];
static ifl_lock_t*            trtLock;
static int                    sysevent_fd;
static token_t                sysevent_token;

static uint8 tskResrcTblCnt              = 0;
static uint8 ifl_default_ctx_enabled     = 0;


/*
 * Static prototypes
 */
static void* _task_manager_thrd (void *value);
static void* _task_thrd (void *value);
static uint8 _get_ctx_id (char* ctx);
static uint8 _get_evt_id (char* event, uint8 addEvent);
static void _init_default_ctx (void);
static void _deinit_task_resource (task_resource_table_t* trtEntry);
static void _dealloc_task_resource (task_resource_t* tResrc);
static task_resource_table_t* _add_entry_to_task_resource_table (char* ctx, uint8 flag);
static task_resource_table_t* _init_task_resource (char* ctx);
static task_resource_t* _lookup_task_resource_table (pid_t tID);
static task_resource_t* _alloc_task_resource (task_resource_table_t* trtEntry);


/*
 * Static API definitions
 */
static uint8 _get_ctx_id (char* ctx)
{
    static uint8 nextCtxIdx = 0;
    uint8 idx = 0;

    for ( ;idx < nextCtxIdx; idx++)
    {
        if (!strncmp(ctxToIdxMap[idx].qCtx, ctx, BUFLEN_16))
        {
            break;
        }
    }
    if (idx == nextCtxIdx || !nextCtxIdx)
    {
        if (nextCtxIdx < IFL_MAX_CONTEXT)
        {
            if (createQ(&ctxToIdxMap[idx=nextCtxIdx].qObj) == IFL_SUCCESS)
            {
                errno_t ret = 0;
                IFL_LOG_INFO("[%d] New Q %p", idx, ctxToIdxMap[idx].qObj);
                ret = strcpy_s(ctxToIdxMap[idx].qCtx, BUFLEN_16, ctx);
                ERR_CHK(ret);
                nextCtxIdx++;
            }
        }
        else
        {
            idx = IFL_MAX_CONTEXT;
        }
    }
    return idx;
}


static uint8 _get_evt_id (char* event, uint8 addEvent)
{
    static uint8 nextEvtHdlIdx = 0;
    uint8  idx = nextEvtHdlIdx;

    if (idx < IFL_MAX_EVENT_HANDLER_MAP)
    {
        for (idx=0; idx < nextEvtHdlIdx; idx++)
        {
            if (!strncmp(evtToHdlMap[idx].event, event, BUFLEN_64))
            {
                break;
            }
        }

        if (addEvent && (idx == nextEvtHdlIdx))
        {
            errno_t ret = strcpy_s(evtToHdlMap[idx].event, BUFLEN_64, event);
            ERR_CHK(ret);
            evtToHdlMap[idx].handlerCount = 0;
            nextEvtHdlIdx++;
        }
    }

    return idx;
}


static task_resource_t* _alloc_task_resource (task_resource_table_t* trtEntry)
{
    task_resource_t* tResrc = trtEntry->tResrc;

    if (trtEntry && tResrc)
    {
        if (tResrc->se_fd)
        {
            IFL_LOG_WARNING("Possible sysevent fd leak!");
        }

        tResrc->se_fd = sysevent_open(LOCALHOST, SE_SERVER_WELL_KNOWN_PORT,
                                                 SE_VERSION, trtEntry->tCtx, &tResrc->se_tok);
        if (!tResrc->se_fd)
        {
            IFL_LOG_ERROR("Failed to open sysevent!");
            tResrc = NULL;
        }
    }
    return tResrc;
}


static void _dealloc_task_resource (task_resource_t* tResrc)
{
    if (tResrc)
    {
        if (tResrc->se_fd)
        {
            sysevent_close(tResrc->se_fd, tResrc->se_tok);
            tResrc->se_fd = 0;
        }
    }
}


static task_resource_table_t* _add_entry_to_task_resource_table (char* ctx, uint8 flag)
{
    task_resource_table_t* retTrt = NULL;
    uint8 tIdx=0;

    for (tIdx=0; tIdx < tskResrcTblCnt; tIdx++)
    {
         if (!strncmp(ctx, tskResrcTbl[tIdx].tCtx, BUFLEN_16))
         {
             IFL_LOG_INFO("ctx %s already exists!", ctx);
             retTrt = &tskResrcTbl[tIdx];
             break;
         }
    }

    if (flag && tIdx == tskResrcTblCnt)
    {
        if (tskResrcTblCnt < IFL_MAX_TASK_RESOURCE)
        {
            errno_t sRet = strcpy_s(tskResrcTbl[tIdx].tCtx, BUFLEN_16, ctx);
            ERR_CHK(sRet);
            tskResrcTbl[tIdx].tResrc = (task_resource_t*)malloc(sizeof(task_resource_t));
            (retTrt = &tskResrcTbl[tIdx])->tResrc->se_fd = 0;
            tskResrcTblCnt++;
        }
        else
        {
            IFL_LOG_ERROR("No more room for task resource table entry!");
        }
    }
    return retTrt;
}


static task_resource_t* _lookup_task_resource_table (pid_t tID)
{
    task_resource_t* tResrc = NULL;

    if (tID)
    {
        for (uint8 idx=0; idx < tskResrcTblCnt; idx++)
        {
            if (tID == tskResrcTbl[idx].tID)
            {
                tResrc = tskResrcTbl[idx].tResrc;
                break;
            }
        }

        /* Lets temporarily have the default ctx inorder not to turn down the request. */
        if (!tResrc && ifl_default_ctx_enabled)
        {   /* The first row in the task resrc tbl is the default ctx, if enabled. */
            tResrc = tskResrcTbl[0].tResrc;
        }
    }
    return tResrc;
}


static task_resource_table_t* _init_task_resource (char* ctx)
{
    task_resource_table_t* trtEntry = NULL;

    ifl_lock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);
       if ((trtEntry = _add_entry_to_task_resource_table(ctx, 0)))
       {
           if (_alloc_task_resource(trtEntry))
           {
               // assignning the threadID of the thread in execution.
               trtEntry->tID  = gettid();
               IFL_LOG_INFO("Updated deferred ctx %d-%s-%d", trtEntry->tID
                                                           , trtEntry->tCtx
                                                           , trtEntry->tResrc->se_fd);
           }
           else
           {
               IFL_LOG_ERROR("Failed to update deferred ctx %s!", trtEntry->tCtx);
           }
       }
       else
       {
           IFL_LOG_INFO("Task resource table entry not found for ctx %s!", ctx);
       }
    ifl_unlock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);

    return trtEntry;
}


static void _deinit_task_resource (task_resource_table_t* trtEntry)
{
    ifl_lock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);
       if (trtEntry)
       {
           trtEntry->tID = 0;
           _dealloc_task_resource(trtEntry->tResrc);
       }
    ifl_unlock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);
}


static void _init_default_ctx (void)
{
    task_resource_table_t* trtEntry = NULL;

    if ((trtEntry = _add_entry_to_task_resource_table("ifl-dflt-ctx", 1)))
    {
        if (_alloc_task_resource(trtEntry))
        {
            // thread ID not required for default context
            trtEntry->tID  = 0;
            IFL_LOG_INFO("Default ctx %d-%s-%d added.", trtEntry->tID
                                                      , trtEntry->tCtx
                                                      , trtEntry->tResrc->se_fd);
            ifl_default_ctx_enabled = 1;
        }
        else
        {
            if (trtEntry->tResrc)
            {
                free(trtEntry->tResrc);
                trtEntry->tResrc = NULL;
            }
            tskResrcTblCnt--;
            IFL_LOG_ERROR("Failed to allocate task resource for default ctx!");
        }
    }
    else
    {
       IFL_LOG_ERROR("Failed to add task resource table entry for default ctx!");
    }
}

/*
 * External API definitions
 */
ifl_ret ifl_init (char* mainCtx)
{
    ifl_ret ret = IFL_SUCCESS;

    memset(evtToHdlMap, 0, sizeof(evtToHdlMap));
    memset(ctxToIdxMap, 0, sizeof(ctxToIdxMap));
    memset(thdToIdxMap, 0, sizeof(thdToIdxMap));

    ifl_thread_init();
    ifl_lock_init(&trtLock);
    _init_default_ctx();

    sysevent_fd = sysevent_open(LOCALHOST, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, mainCtx, &sysevent_token);

    if (IFL_SUCCESS != (ret = ifl_thread_create(0, _task_manager_thrd, NULL)))
    {
        IFL_LOG_ERROR("Failed creating sysevent handler! ret: %d", ret);
    }

    return ret;
}


ifl_ret ifl_init_ctx (char* ctx, ifl_ctx_type cType)
{
    ifl_ret ret = IFL_ERROR;
    task_resource_table_t* trtEntry = NULL;

    if (!ctx || (cType != IFL_CTX_STATIC && cType != IFL_CTX_DYNAMIC))
    {
        IFL_LOG_ERROR("Invalid ctx init %s-%d", ctx, cType);
        return ret;
    }

    ifl_gain_priority();
    ifl_lock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);

    if ((trtEntry = _add_entry_to_task_resource_table(ctx, 1)))
    {
        if (cType == IFL_CTX_STATIC)
        {
            if (trtEntry->tID)
            {
                IFL_LOG_WARNING("Task resource duplication. Skipping(%s)!", ctx);
            }
            else
            if (_alloc_task_resource(trtEntry))
            {
                // assignning the threadID of the thread in execution.
                trtEntry->tID  = gettid();
                IFL_LOG_INFO("New ctx %d-%s-%d added.", trtEntry->tID
                                                      , trtEntry->tCtx
                                                      , trtEntry->tResrc->se_fd);
                ret = IFL_SUCCESS;
            }
            else
            {
                if (trtEntry->tResrc)
                {
                    free(trtEntry->tResrc);
                    trtEntry->tResrc = NULL;
                }
                tskResrcTblCnt--;
                IFL_LOG_ERROR("Failed to allocate task resource for %s", ctx);
            }
        }
        else if (cType == IFL_CTX_DYNAMIC)
        {
            IFL_LOG_INFO("New deferred ctx %s added.", trtEntry->tCtx);
            ret = IFL_SUCCESS;
        }
     }
     else
     {
        IFL_LOG_ERROR("Failed to add task resource table entry for %s!", ctx);
     }

    ifl_unlock(trtLock, IFL_LOCK_TYPE_MUTEX);
    ifl_lose_priority();
  
    return ret;
}

ifl_ret ifl_deinit_ctx (char* ctx)
{
    uint8 tIdx = 0;

    if (ctx)
    {
        ifl_gain_priority();
        ifl_lock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);

        for (tIdx=0; tIdx < tskResrcTblCnt; tIdx++)
        {
            if (!strncmp(ctx, tskResrcTbl[tIdx].tCtx, BUFLEN_16))
            {
                break;
            }
        }

        if (tIdx != tskResrcTblCnt)
        {
            _dealloc_task_resource(tskResrcTbl[tIdx].tResrc);
            free(tskResrcTbl[tIdx].tResrc);

            if (tIdx != tskResrcTblCnt -1 )
            {
                memcpy(&tskResrcTbl[tIdx], &tskResrcTbl[tskResrcTblCnt-1],
                                           sizeof(task_resource_table_t));
                tIdx = tskResrcTblCnt -1;
            }

            tskResrcTbl[tIdx].tResrc = NULL;
            tskResrcTbl[tIdx].tID = 0;
            tskResrcTbl[tIdx].tCtx[0] = '\0';
            tskResrcTblCnt--;
        }

        ifl_unlock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);
        ifl_lose_priority();
    }
    return IFL_SUCCESS;
}

ifl_ret ifl_register_event_handler (char* event, ifl_event_type eType, char* callerCtx, fptr_t cb)
{
    ifl_ret ret = IFL_ERROR;
    uint8 evtID = 0;
    uint8 ctxID = 0;

    if (!event || !callerCtx || !cb)
    {
        IFL_LOG_ERROR("Invalid register args!");
        return ret;
    }

    if ((ctxID = _get_ctx_id(callerCtx)) == IFL_MAX_CONTEXT)
    {
        IFL_LOG_ERROR("Maximum caller context(%d) registered!", IFL_MAX_CONTEXT);
        return ret;
    }
    
    evtID = _get_evt_id(event, 1);
  
    if (evtID == IFL_MAX_EVENT_HANDLER_MAP)
    {
        IFL_LOG_ERROR("Maximum events(%d) registered!", evtID);
        return ret;
    }

    if (evtToHdlMap[evtID].handlerCount < IFL_MAX_CONTEXT)
    {
        evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].ctxID  = ctxID;
        evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].eType  = eType;
        evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].cb     = cb;

        if (eType == IFL_EVENT_NOTIFY)
        {
            sysevent_set_options(sysevent_fd, sysevent_token, evtToHdlMap[evtID].event, TUPLE_FLAG_EVENT);
        }
        sysevent_setnotification(sysevent_fd, sysevent_token, evtToHdlMap[evtID].event, &evtToHdlMap[evtID].asyncID);

        IFL_LOG_INFO("Registered event: %s, ctxID: %d, eType: %d, hdlrCount: %d, evtID: %d, cb: %p"
                                , evtToHdlMap[evtID].event
                                , evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].ctxID
                                , evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].eType
                                , evtToHdlMap[evtID].handlerCount, evtID
                                , evtToHdlMap[evtID].handler[evtToHdlMap[evtID].handlerCount].cb);

        evtToHdlMap[evtID].handlerCount++;
        ret = IFL_SUCCESS;
    }
    else
    {
        IFL_LOG_ERROR("Event(%s) reached max subcription!", evtToHdlMap[evtID].event);
    }

    return ret;
}


/*ifl_ret ifl_unregister_event_handler (char* event, char* callerCtx)
{
    ifl_ret ret = IFL_SUCCESS;

    return ret;
}
*/

ifl_ret ifl_get_event (char* event, char* value, int valueLength)
{
    ifl_ret ret = IFL_SUCCESS;
    task_resource_t* tResrc = NULL;

    ifl_gain_priority();

    ifl_lock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);
       tResrc = _lookup_task_resource_table(gettid());
    ifl_unlock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);

    if (tResrc)
    {
        int sys_ret = 0;
        if ((sys_ret = sysevent_get(tResrc->se_fd, tResrc->se_tok, event, value, valueLength)))
        {
            IFL_LOG_ERROR("SE_GET(%d) %s: %s (err:%d)",  tResrc->se_fd, event, value, sys_ret);
            ret = IFL_SYSEVENT_ERROR;
        }
        else
        {
            IFL_LOG_INFO("SE_GET(%d) %s: %s", tResrc->se_fd, event, value);
        }
    }
    else
    {
        IFL_LOG_ERROR("Failed to lookup task resource!");
        ret = IFL_ERROR;
    }

    ifl_lose_priority();
    return ret;
}


ifl_ret ifl_set_event (char* event, char* value)
{
    ifl_ret ret = IFL_SUCCESS;
    task_resource_t* tResrc = NULL;

    ifl_gain_priority();

    ifl_lock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);
       tResrc = _lookup_task_resource_table(gettid());
    ifl_unlock(trtLock, IFL_LOCK_TYPE_MUTEX_WAIT);

    if (tResrc)
    {
        int sys_ret = 0;
        if ((sys_ret = sysevent_set(tResrc->se_fd, tResrc->se_tok, event, value, 0)))
        {
            IFL_LOG_ERROR("SE_SET(%d) %s: %s (err:%d)",  tResrc->se_fd, event, value, sys_ret);
            ret = IFL_SYSEVENT_ERROR;
        }
        else
        {
            IFL_LOG_INFO("SE_SET(%d) %s: %s", tResrc->se_fd, event, value);
        }
    }
    else
    {
        IFL_LOG_ERROR("Failed to lookup task resource!");
        ret = IFL_ERROR;
    }

    ifl_lose_priority();
    return ret;
}


ifl_ret ifl_deinit(void)
{
    ifl_ret ret = IFL_SUCCESS;

    ifl_deinit_ctx("ifl-dflt-ctx");
    /*
     * Define API
     */
    return ret;
}

static void *_task_manager_thrd(void * value)
{
    UNREFERENCED_PARAMETER(value);
    IFL_LOG_INFO("Created");

    for (;;)
    {
        if (access("/tmp/dhcpmgr_initialized", F_OK) == 0) {
        char event[BUFLEN_64]    = {0};
        char eValue[BUFLEN_64]   = {0};
        int  eventLen  = sizeof(event);
        int  eValueLen = sizeof(eValue);
        int  err = 0;
        async_id_t getnotification_id;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, event, &eventLen,
                                      eValue, &eValueLen, &getnotification_id);

        if (err)
        {
            IFL_LOG_ERROR("Sysevent get notification failed! err: %d", err);
            sleep(2);
        }
        else
        {
            uint8 evtID = 0;
            uint8 ctxID = 0;
            uint8 idx   = 0;

            IFL_LOG_INFO("Event getting triggered is [%s]", event);
            /* _get_evt_id is not thread safe */
            evtID = _get_evt_id(event, 0);
          
            if (evtID == IFL_MAX_EVENT_HANDLER_MAP)
            {
                IFL_LOG_ERROR("Event(%s) not found in registered list! Ambiguous!", event);
                continue;
            }

            for (idx = 0; idx < evtToHdlMap[evtID].handlerCount; idx++)
            {
                ifl_ret ret  = IFL_ERROR;
                ifl_ret retL = IFL_ERROR;
                uint8 skipLock = 0;

                q_data_t* qData = (q_data_t*)malloc(sizeof(q_data_t));
                qData->cb = evtToHdlMap[evtID].handler[idx].cb;
                int rc = strcpy_s(qData->eValue, BUFLEN_64, eValue);
                ERR_CHK(rc);
                ctxID = evtToHdlMap[evtID].handler[idx].ctxID;

                /* spin lock for thread flag - Try */
                if (IFL_SUCCESS == (retL=ifl_thread_lock(ctxID, IFL_LOCK_TYPE_SPIN_NO_WAIT)))
                {
                    if ((skipLock = thdToIdxMap[ctxID]))
                    {
                        ifl_thread_lock(ctxID, IFL_LOCK_TYPE_MUTEX_WAIT);
                    }
                ifl_thread_unlock(ctxID, IFL_LOCK_TYPE_SPIN);
                }
                else
                {
                    if (IFL_LOCK_BUSY == retL)
                    {
                        //IFL_LOG_INFO("[%d] Skip lock acquire.", ctxID);
                    }
                    else
                    {
                        //IFL_LOG_ERROR("[%d] Skip handling event %s", ctxID, event);
                        free(qData);
                        continue;
                    }
                }

                if (IFL_SUCCESS !=
                      (ret = pushToQ(ctxToIdxMap[ctxID].qObj, (void*)qData)))
                {
                    IFL_LOG_ERROR("[%d] Push event %s failed!", ctxID, event);
                }

                if (skipLock)
                {
                    ifl_thread_unlock(ctxID, IFL_LOCK_TYPE_MUTEX);
                }
                else
                {
                    if (IFL_SUCCESS == ret)
                    {
                        void* tData = malloc(sizeof(thread_data_t));
                        ((thread_data_t*)tData)->qObj     = ctxToIdxMap[ctxID].qObj;
                        ((thread_data_t*)tData)->ctxID    = ctxID;

                        thdToIdxMap[ctxID] = 1;

                        if (IFL_SUCCESS !=
                             (ret=ifl_thread_create(IFL_THRD_PROP_DETACH, _task_thrd, tData)))
                        {
                            IFL_LOG_ERROR("[%d] create task thread Failed! Event: %s ret: %d"
                                                                          , ctxID, event, ret);
                            thdToIdxMap[ctxID] = 0;
                        }
                    }
                }
            }
        }
    }
    else{
        sleep(2);
    }
    }
    IFL_LOG_INFO("Exit.");
    return NULL;
}

static void *_task_thrd(void *tData)
{
    ifl_ret retL     = IFL_ERROR;
    q_data_t* qData  = NULL;
    uint8 gotNewTask = 0;
    task_resource_table_t* trtEntry = NULL;
    IFL_LOG_INFO("[%d] Created.", ((thread_data_t*)tData)->ctxID);

    trtEntry = _init_task_resource(ctxToIdxMap[((thread_data_t*)tData)->ctxID].qCtx);

    do {
        while (ifl_thread_lock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_MUTEX),
              popFromQ(((thread_data_t*)tData)->qObj, (void**)&qData) == IFL_SUCCESS)
        {
            ifl_thread_unlock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_MUTEX);
            if (qData)
            {
                IFL_LOG_INFO("[%d] Pop %p", ((thread_data_t*)tData)->ctxID, (void*)qData->cb);
                if (qData->cb)
                {
                    /* Reduce the thrd priority? */
                    ifl_thread_lower_priority(((thread_data_t*)tData)->ctxID);

                    qData->cb(&qData->eValue);

                    /* Reset the thrd priority? */
                    ifl_thread_reset_priority(((thread_data_t*)tData)->ctxID);
                }
                free((void*)qData);
            }
        }
        ifl_thread_unlock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_MUTEX);

        /* not advisable here */
        //ifl_thread_yield();

        if (IFL_SUCCESS ==
                (retL = ifl_thread_lock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_SPIN_NO_WAIT)))
        {
            gotNewTask = 0;
            thdToIdxMap[((thread_data_t*)tData)->ctxID] = 0;
            ifl_thread_unlock(((thread_data_t*)tData)->ctxID, IFL_LOCK_TYPE_SPIN);
        }
        else
        {
            if (IFL_LOCK_BUSY == retL)
            {
                IFL_LOG_INFO("[%d] Reset.", ((thread_data_t*)tData)->ctxID);
                ifl_thread_yield(((thread_data_t*)tData)->ctxID);
                gotNewTask = 1;
            }
        }
    } while (gotNewTask);

    _deinit_task_resource(trtEntry);
    IFL_LOG_INFO("[%d] Exit.", ((thread_data_t*)tData)->ctxID);
    free(tData);

    return NULL;
}
