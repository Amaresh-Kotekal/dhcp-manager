# DHCP Client Manager Architecture

## Component Overview

The DHCP Client Manager architecture is designed around a modular, event-driven approach that provides centralized management of DHCP operations while maintaining clear separation of concerns between different functional areas.

## High-Level Architecture

```mermaid
graph TB
    %% Application Layer - Blue theme
    subgraph APP [" "]
        direction TB
        TR181[TR-181 Data Model]:::appStyle
        RBUS[RBUS/DBUS Interface]:::appStyle
        MGMT[Management APIs]:::appStyle
    end
    
    %% DHCP Manager Core - Green theme
    subgraph CORE [" "]
        direction TB
        CONTROLLER[Main Controller]:::coreStyle
        MONITOR[Lease Monitor]:::coreStyle
        RECOVERY[Recovery Handler]:::coreStyle
    end
    
    %% Protocol Handlers - Orange theme
    subgraph HANDLERS [" "]
        direction TB
        V4HANDLER[DHCPv4 Handler]:::handlerStyle
        V6HANDLER[DHCPv6 Handler]:::handlerStyle
        MAPT[MAP-T Processor]:::handlerStyle
    end
    
    %% External Clients - Purple theme
    subgraph CLIENTS [" "]
        direction LR
        subgraph V4CLIENT [" "]
            UDHCPC[udhcpc Client]:::clientStyle
            V4PLUGIN[udhcpc Plugin]:::pluginStyle
        end
        subgraph V6CLIENT [" "]
            DIBBLER[dibbler Client]:::clientStyle
            V6PLUGIN[dibbler Plugin]:::pluginStyle
        end
    end
    
    %% System Integration - Gray theme
    subgraph SYSTEM [" "]
        direction TB
        NETIF[Network Interfaces]:::systemStyle
        SYSEVENT[System Events]:::systemStyle
        WAN[WAN Manager]:::systemStyle
    end
    
    %% Main control flow - thick lines
    TR181 -.->|Config| CONTROLLER
    RBUS -.->|Commands| CONTROLLER
    MGMT -.->|API Calls| CONTROLLER
    
    %% Core coordination
    CONTROLLER ==>|Control| V4HANDLER
    CONTROLLER ==>|Control| V6HANDLER
    CONTROLLER ==>|Monitor| RECOVERY
    
    %% Lease monitoring flow
    MONITOR ==>|Lease Updates| CONTROLLER
    V4PLUGIN -->|IPC| MONITOR
    V6PLUGIN -->|IPC| MONITOR
    
    %% Client management
    V4HANDLER ==>|Start/Stop| UDHCPC
    V6HANDLER ==>|Start/Stop| DIBBLER
    V6HANDLER -->|Process| MAPT
    
    %% Plugin execution
    UDHCPC -->|Execute| V4PLUGIN
    DIBBLER -->|Execute| V6PLUGIN
    
    %% System integration
    V4HANDLER -->|Configure| NETIF
    V6HANDLER -->|Configure| NETIF
    V4HANDLER -->|Notify| SYSEVENT
    V6HANDLER -->|Notify| SYSEVENT
    CONTROLLER -->|Status| WAN
    
    %% Styling
    classDef appStyle fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#000
    classDef coreStyle fill:#e8f5e8,stroke:#2e7d32,stroke-width:3px,color:#000
    classDef handlerStyle fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#000
    classDef clientStyle fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef pluginStyle fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#000
    classDef systemStyle fill:#f5f5f5,stroke:#616161,stroke-width:2px,color:#000
    
    %% Group styling
    APP ~~~ CORE
    CORE ~~~ HANDLERS
    HANDLERS ~~~ CLIENTS
    CLIENTS ~~~ SYSTEM
```


## Component Responsibilities
![DHCP Manager Block Diagram](../Images/DHCP_mgr_block_diagram.png)

*Figure 1: DHCP Manager Component Block Diagram - Shows the main components and their interactions within the RDK-B DHCP Management system*

### Main Controller
- **Central Coordination**: Orchestrates all DHCP client operations
- **State Management**: Maintains client operational states
- **Interface Monitoring**: Tracks network interface status
- **Configuration Management**: Processes TR-181 configuration changes
- **Error Handling**: Implements recovery and error handling strategies

### Lease Monitor
- **IPC Server**: Receives lease updates from DHCP client plugins
- **Message Routing**: Routes lease information to appropriate handlers
- **Protocol Detection**: Identifies DHCPv4 vs DHCPv6 messages
- **Fast Processing**: Minimal latency message processing

### Protocol Handlers
- **DHCPv4 Handler**: Processes IPv4 lease information and network configuration
- **DHCPv6 Handler**: Processes IPv6 lease information including IANA/IAPD
- **MAP-T Processor**: Handles IPv4-over-IPv6 transition technology

### Recovery Handler
- **Persistence**: Stores lease information for system restart recovery
- **Process Monitoring**: Monitors DHCP client process health
- **State Restoration**: Restores system state after crashes or restarts

## Data Flow Architecture

```mermaid
sequenceDiagram
    participant CONFIG as TR-181 Config
    participant CONTROLLER as Main Controller
    participant CLIENT as DHCP Client
    participant PLUGIN as Client Plugin
    participant HANDLER as Lease Handler
    participant SYSTEM as System/Network
    
    CONFIG->>CONTROLLER: Configuration Change
    CONTROLLER->>CLIENT: Start/Configure Client
    CLIENT->>CLIENT: Acquire Lease
    CLIENT->>PLUGIN: Execute Plugin
    PLUGIN->>CONTROLLER: Send Lease Info (IPC)
    Note over CONTROLLER: IPC Monitoring<br/>handled internally
    CONTROLLER->>HANDLER: Process Lease
    HANDLER->>SYSTEM: Configure Network
    HANDLER->>CONFIG: Update TR-181 Status
    HANDLER->>CONTROLLER: Processing Complete
```

## Threading Model

### Thread Architecture

```mermaid
graph TB
    %% Main Process - Green theme
    subgraph PROCESS [" "]
        direction TB
        MAIN[Main Thread]:::mainStyle
        CONTROLLER_T[Controller Thread<br/>• Client Management<br/>• Lease Monitoring<br/>• Recovery Operations]:::coreStyle
    end
    
    %% External Processes - Purple theme
    subgraph EXTERNAL [" "]
        direction LR
        subgraph CLIENTS [" "]
            UDHCPC_P[udhcpc Process]:::clientStyle
            DIBBLER_P[dibbler Process]:::clientStyle
        end
        subgraph PLUGINS [" "]
            PLUGIN_P[Plugin Processes]:::pluginStyle
        end
    end
    
    %% Thread coordination
    MAIN ==>|Initialize & Start| CONTROLLER_T
    
    %% Process management
    CONTROLLER_T ==>|Spawn/Control| UDHCPC_P
    CONTROLLER_T ==>|Spawn/Control| DIBBLER_P
    
    %% Plugin execution
    UDHCPC_P -->|Execute| PLUGIN_P
    DIBBLER_P -->|Execute| PLUGIN_P
    
    %% IPC communication (handled by controller)
    PLUGIN_P -->|IPC Messages| CONTROLLER_T
    
    %% Recovery operations (part of controller loop)
    CONTROLLER_T -.->|Monitor/Recover| UDHCPC_P
    CONTROLLER_T -.->|Monitor/Recover| DIBBLER_P
    
    %% Styling
    classDef mainStyle fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000
    classDef coreStyle fill:#e8f5e8,stroke:#2e7d32,stroke-width:3px,color:#000
    classDef clientStyle fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef pluginStyle fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#000
    
    %% Group spacing
    PROCESS ~~~ EXTERNAL
```

### Thread Responsibilities

#### Main Thread
- **Initialization**: System startup and component initialization
- **TR-181 Operations**: Handle data model operations
- **RBUS Management**: Manage RBUS/DBUS communications
- **Signal Handling**: Process system signals and shutdown
- **Controller Startup**: Initialize and start the controller thread

#### Controller Thread
The controller thread is the primary worker thread that handles all core DHCP management operations:

- **Client Management**: Start/stop/configure DHCP clients
- **Lease Processing**: Process lease updates from plugins via IPC
- **State Monitoring**: Monitor interface and client states
- **Configuration Updates**: Apply configuration changes
- **Recovery Operations**: Called as APIs before the main controller loop
  - Process health checking and restart operations
  - Lease recovery from persistent storage
  - System state restoration after crashes
- **IPC Listening**: Listen for plugin messages on the IPC socket
- **Message Processing**: Parse and validate lease messages from plugins
- **Data Routing**: Route processed messages to appropriate handlers
- **Error Handling**: Handle communication and operational errors

## Message Flow Patterns

### Lease Acquisition Flow

```mermaid
graph TD
    START[Interface Up] --> CHECK{Interface Ready?}
    CHECK -->|No| WAIT[Wait for Ready]
    WAIT --> CHECK
    CHECK -->|Yes| START_CLIENT[Start DHCP Client]
    START_CLIENT --> DISCOVER[DHCP Discover/Solicit]
    DISCOVER --> RESPONSE{Server Response?}
    RESPONSE -->|No| TIMEOUT[Timeout/Retry]
    TIMEOUT --> DISCOVER
    RESPONSE -->|Yes| PLUGIN[Execute Plugin]
    PLUGIN --> IPC[Send IPC Message]
    IPC --> PROCESS[Process Lease]
    PROCESS --> CONFIGURE[Configure Interface]
    CONFIGURE --> UPDATE[Update TR-181]
    UPDATE --> COMPLETE[Complete]
```

### Error Recovery Flow

```mermaid
graph TD
    ERROR[Error Detected] --> TYPE{Error Type?}
    TYPE -->|Process Died| RESTART[Restart Client]
    TYPE -->|Config Error| RECONFIG[Reconfigure Client]
    TYPE -->|Network Error| RETRY[Retry Operation]
    TYPE -->|Critical Error| DISABLE[Disable Client]
    
    RESTART --> CHECK[Check Recovery]
    RECONFIG --> CHECK
    RETRY --> CHECK
    
    CHECK --> SUCCESS{Recovery OK?}
    SUCCESS -->|Yes| NORMAL[Normal Operation]
    SUCCESS -->|No| ESCALATE[Escalate Error]
    
    DISABLE --> LOG[Log Error]
    ESCALATE --> LOG
    LOG --> COMPLETE[Complete]
    NORMAL --> COMPLETE
```

## Interface Architecture

### Network Interface Integration

```mermaid
graph TB
    %% Network Stack - Blue theme
    subgraph STACK [" "]
        direction TB
        KERNEL[Kernel Network]:::kernelStyle
        NETDEV[Network Devices]:::netStyle
        ROUTES[Routing Table]:::netStyle
        DNS[DNS Configuration]:::netStyle
    end
    
    %% DHCP Manager - Green theme (limited scope)
    subgraph DHCP [" "]
        direction TB
        CONTROLLER[Controller]:::coreStyle
        V4HANDLER[DHCPv4 Handler<br/>• Interface IP Config<br/>• Lease Processing]:::handlerStyle
        V6HANDLER[DHCPv6 Handler<br/>• Interface IPv6 Config<br/>• Prefix Assignment]:::handlerStyle
    end
    
    %% WAN Manager - Orange theme (system integration)
    subgraph WAN_MGR [" "]
        direction TB
        WAN[WAN Manager<br/>• Default Routes<br/>• DNS Configuration<br/>• Firewall Rules]:::wanStyle
        SYSEVENT[System Events]:::systemStyle
    end
    
    %% System Integration - Gray theme
    subgraph INTEGRATION [" "]
        direction TB
        FIREWALL[Firewall]:::systemStyle
        ROUTING[Routing Daemon]:::systemStyle
    end
    
    %% DHCP Manager - Interface only configuration
    CONTROLLER ==>|Interface Control| NETDEV
    V4HANDLER ==>|Configure Interface IP| NETDEV
    V6HANDLER ==>|Configure Interface IPv6| NETDEV
    
    %% DHCP Manager - Lease status reporting
    V4HANDLER -->|Lease Status| SYSEVENT
    V6HANDLER -->|Lease Status| SYSEVENT
    
    %% WAN Manager - System configuration
    WAN ==>|Default Routes| ROUTES
    WAN ==>|DNS Servers| DNS
    WAN ==>|Firewall Rules| FIREWALL
    WAN -->|Route Updates| ROUTING
    
    %% Event-driven integration
    SYSEVENT ==>|Lease Events| WAN
    
    %% Kernel interaction
    NETDEV -.->|Interface State| KERNEL
    ROUTES -.->|Kernel Routes| KERNEL
    DNS -.->|Resolver Config| KERNEL
    
    %% Styling
    classDef kernelStyle fill:#e8eaf6,stroke:#3f51b5,stroke-width:3px,color:#000
    classDef netStyle fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#000
    classDef coreStyle fill:#e8f5e8,stroke:#2e7d32,stroke-width:3px,color:#000
    classDef handlerStyle fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef wanStyle fill:#fff3e0,stroke:#f57c00,stroke-width:3px,color:#000
    classDef systemStyle fill:#f5f5f5,stroke:#616161,stroke-width:2px,color:#000
    
    %% Group spacing
    STACK ~~~ DHCP
    DHCP ~~~ WAN_MGR
    WAN_MGR ~~~ INTEGRATION
```

### TR-181 Integration Points

The DHCP Manager integrates with TR-181 at multiple levels:

#### Configuration Parameters
- `Device.DHCPv4.Client.{i}.*` - DHCPv4 client configuration
- `Device.DHCPv6.Client.{i}.*` - DHCPv6 client configuration
- Custom vendor parameters and extensions

#### Status Parameters
- Lease information and status
- Client operational state
- Error conditions and diagnostics
- Performance metrics

#### Operational Commands
- Client enable/disable operations
- Lease renewal commands
- Reset and restart operations
- Diagnostic commands

## Security Architecture

### Process Isolation

```mermaid
graph TB
    %% Privileged Context - Red theme (highest privilege)
    subgraph PRIVILEGED [" "]
        direction TB
        MANAGER[DHCP Manager]:::privilegedStyle
        CONTROLLER[Controller]:::privilegedStyle
    end
    
    %% Network Context - Blue theme (network operations)
    subgraph NETWORK [" "]
        direction LR
        UDHCPC[udhcpc Client]:::networkStyle
        DIBBLER[dibbler Client]:::networkStyle
    end
    
    %% Plugin Context - Purple theme (plugin execution)
    subgraph PLUGIN [" "]
        direction LR
        V4PLUGIN[udhcpc Plugin]:::pluginStyle
        V6PLUGIN[dibbler Plugin]:::pluginStyle
    end
    
    %% System Context - Orange theme (system resources)
    subgraph SYSTEM [" "]
        direction TB
        NETCONFIG[Network Config]:::systemStyle
        FILESYSTEM[File System]:::systemStyle
    end
    
    %% Control flows (privileged to network)
    MANAGER ==>|Manage| CONTROLLER
    CONTROLLER ==>|Control| UDHCPC
    CONTROLLER ==>|Control| DIBBLER
    
    %% Plugin execution flows
    UDHCPC -->|Execute| V4PLUGIN
    DIBBLER -->|Execute| V6PLUGIN
    
    %% Plugin communication (isolated)
    V4PLUGIN -.->|IPC| MANAGER
    V6PLUGIN -.->|IPC| MANAGER
    
    %% System resource access (privileged only)
    CONTROLLER ==>|Configure| NETCONFIG
    CONTROLLER ==>|Persist| FILESYSTEM
    
    %% Security boundaries (dotted lines)
    NETCONFIG -.->|Read-only| UDHCPC
    NETCONFIG -.->|Read-only| DIBBLER
    
    %% Styling
    classDef privilegedStyle fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#000
    classDef networkStyle fill:#e3f2fd,stroke:#1976d2,stroke-width:2px,color:#000
    classDef pluginStyle fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef systemStyle fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#000
    
    %% Group spacing
    PRIVILEGED ~~~ NETWORK
    NETWORK ~~~ PLUGIN
    PLUGIN ~~~ SYSTEM
```

## DHCP Protocol Sequences

### DHCPv4 Sequence Flow

![DHCPv4 Sequence Diagram](../Images/DHCP_v4_sequence.png)

*Figure 2: DHCPv4 Sequence Diagram - Shows the complete DHCPv4 lease acquisition and processing flow from client startup through network configuration*

The DHCPv4 sequence illustrates the interaction between the DHCP Manager, udhcpc client, and the udhcpc plugin during lease acquisition:

1. **Client Initialization**: Main controller starts udhcpc client based on TR-181 configuration
2. **DHCP Discovery**: udhcpc performs standard DHCP discovery process (DISCOVER/OFFER/REQUEST/ACK)
3. **Plugin Execution**: Upon lease acquisition, udhcpc executes the plugin with lease information
4. **IPC Communication**: Plugin sends lease data to the controller via IPC
5. **Lease Processing**: Controller processes the lease and updates interface configuration
6. **Interface Configuration**: Interface is configured with IP address and interface-specific settings
7. **System Events**: Lease status events are sent to system for WAN Manager processing
8. **WAN Manager Integration**: WAN Manager handles default routes, DNS, and firewall configuration
9. **Status Update**: TR-181 data model is updated with current lease information

### DHCPv6 Sequence Flow

![DHCPv6 Sequence Diagram](../Images/DHCP_v6_sequence.png)

*Figure 3: DHCPv6 Sequence Diagram - Shows the complete DHCPv6 lease acquisition and processing flow including IANA and IAPD handling*

The DHCPv6 sequence demonstrates the more complex IPv6 lease acquisition process:

1. **Client Initialization**: Main controller starts dibbler client with IPv6-specific configuration
2. **DHCPv6 Solicitation**: dibbler performs DHCPv6 solicitation process (SOLICIT/ADVERTISE/REQUEST/REPLY)
3. **Dual Association**: Handles both IANA (Identity Association for Non-temporary Addresses) and IAPD (Identity Association for Prefix Delegation)
4. **Plugin Execution**: dibbler executes the plugin with comprehensive IPv6 lease information
5. **IPC Communication**: Plugin sends detailed IPv6 lease data including addresses and prefixes
6. **Lease Processing**: Controller processes both address assignments and prefix delegations
7. **Interface Configuration**: Interface is configured with IPv6 addresses and prefixes
8. **System Events**: IPv6-specific lease events are generated for WAN Manager processing
9. **WAN Manager Integration**: WAN Manager handles IPv6 default routes, DNS, and system configuration
10. **Status Update**: TR-181 data model is updated with IPv6 lease information

## Extension Points

### Plugin Architecture
- **Client Plugins**: Extend support to new DHCP clients
- **Protocol Extensions**: Add support for new DHCP options
- **Custom Handlers**: Implement custom lease processing
- **Integration Hooks**: Add hooks for external system integration

### Configuration Extensions
- **Custom Options**: Support for vendor-specific options
- **Policy Engines**: Pluggable policy decision engines
- **Validation Rules**: Custom validation rule engines
- **Event Handlers**: Custom event processing extensions

This architectural documentation provides the foundation for understanding how the DHCP Client Manager components interact and can be extended or modified to meet specific deployment requirements.