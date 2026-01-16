#include "sm_DhcpMgr.h"
#include "dhcpmgr_rbus_apis.h"
#include <unistd.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include "util.h"


#define SERVER_BIN "dibbler-server"
/* Define the global MQ descriptors declared in mq_shared.h */
mqd_t mq_dispatch = (mqd_t)-1; /* MQ_NAME (/lan_sm_queue) */
mqd_t mq_fsm = (mqd_t)-1;      /* SM_MQ_NAME (/lan_fsm_queue) */

static DHCPS_State mainState = DHCPS_STATE_IDLE;

int PrepareConfigv4s(void *payload);
int Startv4s(void *payload);
int Stopv4s(void *payload);
int PrepareConfigv6s(void *payload);
int Startv6s(void *payload);
int Stopv6s(void *payload);

GlobalDhcpConfig sGlbDhcpCfg;
DhcpInterfaceConfig **ppDhcpCfgs;
static bool Dns_only = false;

const char* DhcpManagerEvent_Names[]={
    "EVENT_CONFIGUREv4",
    "EVENT_CONFIG_CHANGEDv4",
    "EVENT_CONFIG_SAMEv4",
    "EVENT_STARTEDv4",
    "EVENT_STOPv4",
    "EVENT_STOPPEDv4",
    "EVENT_CONFIGUREv6",
    "EVENT_CONFIG_CHANGEDv6",
    "EVENT_CONFIG_SAMEv6",
    "EVENT_STARTEDv6",
    "EVENT_STOPv6",
    "EVENT_STOPPEDv6"
};

DHCPS_SM_Mapping gSM_StateObj[] = {

    // -------------------- Start/Restart v4 --------------------
    { DHCPS_STATE_IDLE, EVENT_CONFIGUREv4, DHCPS_STATE_PREPARINGv4, PrepareConfigv4s },
    { DHCPS_STATE_PREPARINGv4, EVENT_CONFIG_CHANGEDv4, DHCPS_STATE_STARTINGv4, Startv4s },
    { DHCPS_STATE_PREPARINGv4, EVENT_CONFIG_SAMEv4, DHCPS_STATE_IDLE, NULL },
    { DHCPS_STATE_STARTINGv4, EVENT_STARTEDv4, DHCPS_STATE_IDLE, NULL },

    // -------------------- Stop v4 --------------------
    { DHCPS_STATE_IDLE, EVENT_STOPv4, DHCPS_STATE_STOPPINGv4, Stopv4s },
    { DHCPS_STATE_STOPPINGv4, EVENT_STOPPEDv4, DHCPS_STATE_IDLE, NULL },

    // -------------------- Start/Restart v6 --------------------
    { DHCPS_STATE_IDLE, EVENT_CONFIGUREv6, DHCPS_STATE_PREPARINGv6, PrepareConfigv6s },
    { DHCPS_STATE_PREPARINGv6, EVENT_CONFIG_CHANGEDv6, DHCPS_STATE_STARTINGv6, Startv6s },
    { DHCPS_STATE_PREPARINGv6, EVENT_CONFIG_SAMEv6, DHCPS_STATE_IDLE, NULL },
    { DHCPS_STATE_STARTINGv6, EVENT_STARTEDv6, DHCPS_STATE_IDLE, NULL },

    // -------------------- Stop v6 --------------------
    { DHCPS_STATE_IDLE, EVENT_STOPv6, DHCPS_STATE_STOPPINGv6, Stopv6s },
    { DHCPS_STATE_STOPPINGv6, EVENT_STOPPEDv6, DHCPS_STATE_IDLE, NULL },

};

/* Post a dispatch event to the central dispatch queue opened by main */
void PostEvent(DhcpManagerEvent evt) {
    /* Post DhcpManagerEvent to the FSM queue (mq_fsm).
     * Previously this sent events to mq_dispatch which is the same
     * queue FSMThread reads from; that produced a feedback loop
     * (dispatch -> post -> dispatch...). Use mq_fsm so the
     * FSM_Dispatch_Thread receives DhcpManagerEvent values.
     */ 
    if (mq_fsm == (mqd_t)-1) {
        DHCPMGR_LOG_ERROR("%s:%d PostEvent: FSM MQ not initialized\n", __FUNCTION__, __LINE__);
        return;
    }
    if (mq_send(mq_fsm, (const char *)&evt, sizeof(evt), 0) == -1) {
        DHCPMGR_LOG_ERROR("%s:%d PostEvent: mq_send failed: %s", __FUNCTION__, __LINE__, strerror(errno));
    } else {
        DHCPMGR_LOG_INFO("%s:%d PostEvent: Event %d sent to FSM message queue %s\n", __FUNCTION__, __LINE__, evt, SM_MQ_NAME);
    }
}

//THIS FUNCTION IS USED TO GET EVENT NAME STRING FROM ENUM VALUE
const char* GetEventName(DhcpManagerEvent evt) {
    if (evt >= 0 && evt < sizeof(DhcpManagerEvent_Names)/sizeof(DhcpManagerEvent_Names[0])) {
        return DhcpManagerEvent_Names[evt];
    }
    return "UNKNOWN_EVENT";
}

void DispatchDHCP_SM(DhcpManagerEvent evt, void *payload) {
    DHCPMGR_LOG_INFO("%s:%d [FSM] DispatchDHCP_SM called with event %s\n", __FUNCTION__, __LINE__, GetEventName(evt));
    // Simple stub: find matching state and call action
    for (int i = 0; i < (int)(sizeof(gSM_StateObj)/sizeof(gSM_StateObj[0])); i++) {
        if (gSM_StateObj[i].curState == (int)mainState && gSM_StateObj[i].event == (int)evt) {
            if (gSM_StateObj[i].action) {
                if(gSM_StateObj[i].action(payload) == 0) {
                    DHCPMGR_LOG_INFO("%s:%d [FSM] Action for event %s executed successfully.\n", __FUNCTION__, __LINE__, GetEventName(evt));
                } else {
                    DHCPMGR_LOG_ERROR("%s:%d [FSM] Action for event %s failed.\n", __FUNCTION__, __LINE__, GetEventName(evt));
                    return; // Do not change state if action fails
                }
            }
            mainState = gSM_StateObj[i].nextState;
            break;
        }
    }
}

int PrepareConfigv6s(void *payload) 
{
    (void)payload;
    bool statefull_enabled = false;
    bool stateless_enabled = false;
    int LanConfig_count = 0;
    DhcpPayload lanConfigs[MAX_IFACE_COUNT];
    dhcp_server_publish_state(DHCPS_STATE_PREPARINGv6);
    GetLanDHCPConfig(lanConfigs, &LanConfig_count);
    if (check_ipv6_received(lanConfigs, LanConfig_count, &statefull_enabled, &stateless_enabled) != 0) {
        DHCPMGR_LOG_ERROR("%s:%d No brlan0 interface with DHCPv6 enabled. Skipping DHCPv6 configuration.\n", __FUNCTION__, __LINE__);
        return -1;
    }
    else
    {
        if (statefull_enabled)
        {
            DHCPMGR_LOG_INFO("%s:%d Stateful DHCPv6 is enabled on brlan0.\n", __FUNCTION__, __LINE__);
            //As of now its hardcoded to call create_dhcpsv6_config function for brlan0 only
            int ret = create_dhcpsv6_config(lanConfigs, LanConfig_count, statefull_enabled);
            if (ret != 0)
            {
                DHCPMGR_LOG_ERROR("%s:%d Failed to create DHCPv6 configuration.\n", __FUNCTION__, __LINE__);
                return -1;
            }
        }
    }
    DHCPMGR_LOG_INFO("%s:%d DHCPv6 configuration (stub) PREPARING Done !!!\n", __FUNCTION__, __LINE__);
    PostEvent(EVENT_CONFIG_CHANGEDv6);
    return 0;
}

int PrepareConfigv4s(void *payload) {
    (void)payload;
    char *dnsonly = Dns_only ? "true" : NULL;
    memset(&sGlbDhcpCfg, 0, sizeof(GlobalDhcpConfig));
    int LanConfig_count = 0;
    char dhcpOptions[1024] = {0};
    DhcpPayload lanConfigs[MAX_IFACE_COUNT];
    bool serverInitstate = false;
    dhcp_server_publish_state(DHCPS_STATE_PREPARINGv4);

    // Stub function for fetching lanConfigs and LanConfig_count from somewhere
    GetLanDHCPConfig(lanConfigs, &LanConfig_count);
    AllocateDhcpInterfaceConfig(&ppDhcpCfgs, LanConfig_count);
    Add_inf_to_dhcp_config(lanConfigs, MAX_IFACE_COUNT, ppDhcpCfgs, LanConfig_count);
    Construct_dhcp_configurationv4(dhcpOptions, dnsonly);
    sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs = (char **)malloc(sizeof(char *));
    if (sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs == NULL)
    {
        DHCPMGR_LOG_ERROR("%s:%d Memory allocation for ppCmdLineArgs failed\n", __FUNCTION__, __LINE__);
        return -1;
    }
    sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs[0] = (char *)malloc(1024 * sizeof(char));
    if (sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs[0] == NULL)
    {
        DHCPMGR_LOG_ERROR("%s:%d Memory allocation for ppCmdLineArgs[0] failed\n", __FUNCTION__, __LINE__);
        free(sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs);
        sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs = NULL;
        return -1;
    }
    memset(sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs[0], 0, 1024);
    snprintf(sGlbDhcpCfg.sCmdArgs.ppCmdLineArgs[0], 1024, "%s", dhcpOptions);
    sGlbDhcpCfg.sCmdArgs.iNumOfArgs = 1;
    serverInitstate = dhcpServerInit(&sGlbDhcpCfg, ppDhcpCfgs, LanConfig_count);
    if (!serverInitstate) {
        DHCPMGR_LOG_ERROR("%s:%d DHCP Server Initialization failed\n", __FUNCTION__, __LINE__);
        return -1;
    }
    else 
    {
        if (Dns_only)
        {
            dns_only(); //stub function call to mask the interface in dnsmasq.conf 
            Dns_only = false;
        }
        DHCPMGR_LOG_INFO("%s:%d DHCP Server Initialization successful\n", __FUNCTION__, __LINE__);
        PostEvent(EVENT_CONFIG_CHANGEDv4);
    }
    return 0;
}

int Startv4s(void *payload) {
    (void)payload;
    bool serverStartState = false;
    dhcp_server_publish_state(DHCPS_STATE_STARTINGv4);
    serverStartState =  dhcpServerStart(&sGlbDhcpCfg);
    if (!serverStartState) {
        DHCPMGR_LOG_ERROR("%s:%d DHCP Server Start failed,Moving back to Idle state\n", __FUNCTION__, __LINE__);
        mainState = DHCPS_STATE_IDLE;
        dhcp_server_publish_state(DHCPS_STATE_IDLE);
        return -1;
    }
    else 
    {
        DHCPMGR_LOG_INFO("%s:%d DHCP Server Started successfully\n", __FUNCTION__, __LINE__);
    PostEvent(EVENT_STARTEDv4);
        dhcp_server_publish_state(DHCPS_STATE_IDLE);
    }
    return 0;
}

int Stopv4s( void *payload) {
    (void)payload;
    dhcp_server_publish_state(DHCPS_STATE_STOPPINGv4);
    dhcpServerStop(NULL, 0);
    Dns_only = true;
    DHCPMGR_LOG_INFO("%s:%d DHCP Server Stopped successfully\n", __FUNCTION__, __LINE__);
    PostEvent(EVENT_STOPPEDv4);
    dhcp_server_publish_state(DHCPS_STATE_IDLE);
    PostEvent(EVENT_CONFIGUREv4);
    return 0;
}

int Startv6s(void *payload) {
    (void)payload;
    dhcp_server_publish_state(DHCPS_STATE_STARTINGv6);
    DHCPMGR_LOG_INFO("%s:%d Starting DHCPv6 server\n", __FUNCTION__, __LINE__);
//    dhcpv6_server_start(SERVER_BIN, DHCPV6_SERVER_TYPE_STATEFUL);
    PostEvent(EVENT_STARTEDv6);
    dhcp_server_publish_state(DHCPS_STATE_IDLE);
    return 0;
}

int Stopv6s( void *payload) {
    (void)payload;
    dhcp_server_publish_state(DHCPS_STATE_STOPPINGv6);
//    dhcpv6_server_stop(SERVER_BIN, DHCPV6_SERVER_TYPE_STATEFUL); // Using stateful to stop the server as a stub
    PostEvent(EVENT_STOPPEDv6);
    dhcp_server_publish_state(DHCPS_STATE_IDLE);
    DHCPMGR_LOG_INFO("%s:%d Stopping DHCPv6 server\n", __FUNCTION__, __LINE__);
    return 0;
}

// FSM thread: dispatch events
void* FSM_Dispatch_Thread(void* arg) 
{
    (void)arg;
    mqd_t mq;
//    struct mq_attr attr;
    ssize_t n;
    DhcpManagerEvent mq_event;
    char *buf = NULL;

    /* Use the centrally opened FSM MQ descriptor (mq_fsm) */
    mq = mq_fsm;
    if (mq == (mqd_t)-1) {
        DHCPMGR_LOG_ERROR("%s:%d FSM_Dispatch_Thread: mq_fsm not initialized\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    /* allocate buffer based on actual queue msgsize to avoid EMSGSIZE */
    struct mq_attr qattr;
    if (mq_getattr(mq, &qattr) == -1) {
        DHCPMGR_LOG_ERROR("%s:%d FSM_Dispatch_Thread: mq_getattr failed: %s", __FUNCTION__, __LINE__, strerror(errno));
        return NULL;
    }
    size_t msgsize = (size_t)qattr.mq_msgsize;
    buf = malloc(msgsize);
    if (!buf) {
        DHCPMGR_LOG_ERROR("%s:%d FSM_Dispatch_Thread: malloc failed: %s", __FUNCTION__, __LINE__, strerror(errno));
        return NULL;
    }

    DHCPMGR_LOG_INFO("%s:%d FSM_Dispatch_Thread: listening on FSM MQ %s (msgsize=%ld)\n", __FUNCTION__, __LINE__, SM_MQ_NAME, (long)msgsize);

    while (1) {
        n = mq_receive(mq, buf, msgsize, NULL);
        if (n >= 0) {
            if (n >= (ssize_t)sizeof(mq_event)) {
                memcpy(&mq_event, buf, sizeof(mq_event));
                DHCPMGR_LOG_INFO("%s:%d FSM_Dispatch_Thread: received event %d from MQ\n", __FUNCTION__, __LINE__, mq_event);
                DispatchDHCP_SM(mq_event, NULL);
            } else {
                DHCPMGR_LOG_ERROR("%s:%d FSM_Dispatch_Thread: received message too small (%ld bytes)\n", __FUNCTION__, __LINE__, (long)n);
            }
        } 
        else 
        {
            if (errno == EINTR) continue;
            DHCPMGR_LOG_ERROR("%s:%d FSM_Dispatch_Thread: mq_receive failed: %s", __FUNCTION__, __LINE__, strerror(errno));
            break;
        }
    }

    free(buf);
    /* do not close mq_fsm here; main owns it */
    return NULL;
}

/* FSM thread: read DhcpManagerEvent values from the MQ and dispatch to the DHCP FSM */
void *FSMThread(void *arg)
{
    (void)arg;
    mqd_t mq;
//    struct mq_attr attr;
    ssize_t n;
    DhcpMgr_DispatchEvent evt;
    char *buf = NULL;

    /* Use the centrally opened dispatch MQ descriptor (mq_dispatch) */
    mq = mq_dispatch;
    if (mq == (mqd_t)-1) {
        DHCPMGR_LOG_ERROR("%s:%d FSMThread: mq_dispatch not initialized\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    struct mq_attr qattr;
    if (mq_getattr(mq, &qattr) == -1) {
        DHCPMGR_LOG_ERROR("%s:%d FSMThread: mq_getattr failed: %s", __FUNCTION__, __LINE__, strerror(errno));
        return NULL;
    }
    size_t msgsize = (size_t)qattr.mq_msgsize;
    buf = malloc(msgsize);
    if (!buf) {
        DHCPMGR_LOG_ERROR("%s:%d FSMThread: malloc failed: %s", __FUNCTION__, __LINE__, strerror(errno));
        return NULL;
    }

    DHCPMGR_LOG_INFO("%s:%d FSMThread: listening on Dispatch MQ (msgsize=%ld)\n", __FUNCTION__, __LINE__, (long)msgsize);

    while (1) {
        n = mq_receive(mq, buf, msgsize, NULL);
        if (n >= 0) 
        {
            if (n >= (ssize_t)sizeof(evt)) {
                memcpy(&evt, buf, sizeof(evt));
                DHCPMGR_LOG_INFO("%s:%d FSMThread: received dispatch event %d from MQ\n", __FUNCTION__, __LINE__, evt);
                /* Map DhcpMgr_DispatchEvent -> DhcpManagerEvent for PostEvent */
                DhcpManagerEvent post_evt;
                switch (evt) {
                    case DM_EVENT_STARTv4:
                        post_evt = EVENT_CONFIGUREv4; /* start => configure/start flow */
                        break;
                    case DM_EVENT_RESTARTv4:
                        post_evt = EVENT_CONFIGUREv4; /* restart treated like configure */
                        break;
                    case DM_EVENT_CONF_CHANGEDv4:
                        post_evt = EVENT_CONFIG_CHANGEDv4;
                        break;
                    case DM_EVENT_STOPv4:
                        post_evt = EVENT_STOPv4;
                        break;
                    case DM_EVENT_STARTv6:
                        post_evt = EVENT_CONFIGUREv6;
                        break;
                    case DM_EVENT_RESTARTv6:
                        post_evt = EVENT_CONFIGUREv6;
                        break;
                    case DM_EVENT_CONF_CHANGEDv6:
                        post_evt = EVENT_CONFIG_CHANGEDv6;
                        break;
                    case DM_EVENT_STOPv6:
                        post_evt = EVENT_STOPv6;
                        break;
                    default:
                        DHCPMGR_LOG_ERROR("%s:%d FSMThread: unknown dispatch event %d\n", __FUNCTION__, __LINE__, evt);
                        continue;
                }
                PostEvent(post_evt);
            } 
            else 
            {
                DHCPMGR_LOG_ERROR("%s:%d FSMThread: received message too small (%ld bytes)\n", __FUNCTION__, __LINE__, (long)n);
            }
        } 
        else {
            if (errno == EINTR) continue;
            DHCPMGR_LOG_ERROR("%s:%d FSMThread: mq_receive failed: %s", __FUNCTION__, __LINE__, strerror(errno));
            break;
        }
    }

    free(buf);
    /* do not close mq_dispatch here; main owns it */
    return NULL;
}

/* Cleanup handler: close and unlink message queues then exit */
static void cleanup_handler(int signo)
{
    DHCPMGR_LOG_INFO("%s:%d Received signal %d, cleaning up...\n", __FUNCTION__, __LINE__, signo);
    if (mq_dispatch != (mqd_t)-1) {
        mq_close(mq_dispatch);
        mq_unlink(MQ_NAME);
        mq_dispatch = (mqd_t)-1;
        DHCPMGR_LOG_INFO("%s:%d Closed and unlinked dispatch MQ %s\n", __FUNCTION__, __LINE__, MQ_NAME);
    }
    if (mq_fsm != (mqd_t)-1) {
        mq_close(mq_fsm);
        mq_unlink(SM_MQ_NAME);
        mq_fsm = (mqd_t)-1;
        DHCPMGR_LOG_INFO("%s:%d Closed and unlinked FSM MQ %s\n", __FUNCTION__, __LINE__, SM_MQ_NAME);
    }
    exit(0);
}


int dhcp_server_init_main() {
    
    DHCPMGR_LOG_INFO("%s:%d DHCP Manager starting...\n", __FUNCTION__, __LINE__);
    DhcpMgr_Rbus_Init(); // Initialize rbus
    /* Create/open the message queues centrally so other libraries can use the descriptors.
       mq_dispatch corresponds to MQ_NAME (dispatch queue, holds DhcpMgr_DispatchEvent values)
       mq_fsm corresponds to SM_MQ_NAME (fsm queue, holds DhcpManagerEvent values)
    */
    struct mq_attr attr;

    /* Create dispatch queue (MQ_NAME) */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = sizeof(DhcpMgr_DispatchEvent);
    attr.mq_curmsgs = 0;
    mq_dispatch = mq_open(MQ_NAME, O_CREAT | O_RDWR, 0666, &attr);
    if (mq_dispatch == (mqd_t)-1) {
        DHCPMGR_LOG_ERROR("%s:%d mq_open MQ_NAME failed: %s\n", __FUNCTION__, __LINE__, strerror(errno));
    } else {
        DHCPMGR_LOG_INFO("%s:%d Opened dispatch MQ %s (msgsize=%ld)\n", __FUNCTION__, __LINE__, MQ_NAME, (long)attr.mq_msgsize);
    }

    /* Create FSM action queue (SM_MQ_NAME) */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = sizeof(DhcpManagerEvent);
    attr.mq_curmsgs = 0;
    mq_fsm = mq_open(SM_MQ_NAME, O_CREAT | O_RDWR, 0666, &attr);
    if (mq_fsm == (mqd_t)-1) {
        DHCPMGR_LOG_ERROR("%s:%d mq_open SM_MQ_NAME failed: %s\n", __FUNCTION__, __LINE__, strerror(errno));
    } else {
        DHCPMGR_LOG_INFO("%s:%d Opened FSM MQ %s (msgsize=%ld)\n", __FUNCTION__, __LINE__, SM_MQ_NAME, (long)attr.mq_msgsize);
    }

    /* Start FSM threads declared in sm_DhcpMgr.h
       - FSMThread listens on MQ_NAME ("/lan_sm_queue") and posts dispatch events
       - FSM_Dispatch_Thread listens on SM_MQ_NAME ("/lan_fsm_queue") and executes actions
    */
    pthread_t fsm_tid, dispatch_tid;
    if (pthread_create(&fsm_tid, NULL, FSMThread, NULL) != 0) {
        DHCPMGR_LOG_ERROR("%s:%d pthread_create FSMThread failed: %s\n", __FUNCTION__, __LINE__, strerror(errno));
    } else {
        pthread_detach(fsm_tid);
    }

    if (pthread_create(&dispatch_tid, NULL, FSM_Dispatch_Thread, NULL) != 0) {
        DHCPMGR_LOG_ERROR("%s:%d pthread_create FSM_Dispatch_Thread failed: %s\n", __FUNCTION__, __LINE__, strerror(errno));
    } else {
        pthread_detach(dispatch_tid);
    }

    /* register handler for SIGINT and SIGTERM */
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    dhcp_server_signal_state_machine_ready(); // Signal that the state machine is ready
    dhcp_server_publish_state(DHCPS_STATE_IDLE); // Publish initial state

    /* Keep the main thread alive; threads run the FSM and MQ handling */
    while (1) {
        pause(); /* wait for signals; lightweight sleep */
    }


    return 0;
}
