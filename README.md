#DHCPManager

DHCPManager is a modular and flexible system designed to manage DHCP (Dynamic Host Configuration Protocol) functionalities for both IPv4 and IPv6. It supports client and server configurations and is intended for use in embedded or networked devices, such as those running RDK (Reference Design Kit).
DHCPManager is not a standalone binary. It must be compiled with RDKB (Reference Design Kit for Broadband) components. The project provides a comprehensive solution for managing DHCP-related functionalities, including support for DHCPv4 and DHCPv6 client and server modules.

#Features
•	Supports DHCPv4 and DHCPv6
•	Modular architecture for easy integration and extension
•	Manages both client and server configurations
•	Designed for embedded systems and network appliances
•	Compatible with RDKB-based platforms
•	Publishes DHCP lease events to Subscribers
•	Supports LAN-side DHCP server for IPv4 and IPv6

🛠️ Build Instructions
DHCPManager is designed to be compiled and integrated with RDKB components. It is not a standalone binary.

To build DHCPManager as part of the RDKB build system:

1.	Ensure you have the RDKB build environment set up.
2.	Clone the DHCPManager repository into the appropriate RDKB source directory.
3.	Include DHCPManager Distro (dhcp_manager) in your RDKB build configuration.
4.	Run the RDKB build process to compile DHCPManager along with other components.
5.	Refer to the RDKB documentation for detailed build and integration steps. (From RC2.11.0a, The DHCPMANAGER APIs will be supported in meta-rdk-wan)

⚙️ Functional Description
DHCPManager acts as a controller and orchestrator for DHCP utilities and services:

•	It creates configuration files for starting DHCPv6 or DHCPv4 utilities.
•	It triggers these utilities based on system events and network interface states.
•	It monitors and maintains lease information, including IP addresses, lease durations, and renewal status.
•	On events such as renewal, lease failure, or expiration, it publishes updates to WANMANAGER, ensuring the system remains aware of network status.
•	In future versions, on the LAN side, DHCPManager starts and manages DHCPv4 and DHCPv6 servers to provide IP addresses and configuration to LAN clients connected to the RDKB gateway.
•	This design ensures robust and dynamic DHCP handling across both WAN and LAN interfaces.

📚 Documentation

For comprehensive documentation including architecture details, configuration guides, and component specifications, see:

**[📖 Complete Documentation](docs/README.md)**

The documentation includes:
- System architecture and component diagrams
- Threading model and data flow patterns
- Configuration guide with PSM parameters
- Component-specific documentation
- Integration with WAN Manager and TR-181

🤝 Contribution Guidelines
Contributions are welcome! To contribute:

1.	Fork the repository.
2.	Create a feature or bugfix branch.
3. Make your changes and ensure they are thoroughly tested.
4.	Submit a pull request with a clear description of your changes.
5. Please adhere to the coding standards used in the project and include relevant documentation or test cases.

