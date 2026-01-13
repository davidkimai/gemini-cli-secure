/**
 * Capability taxonomy for gemini-cli-secure
 * Defines atomic permissions for tool operations
 */

export enum Capability {
    // Filesystem capabilities
    FILESYSTEM_READ = 'filesystem.read',
    FILESYSTEM_WRITE = 'filesystem.write',
    FILESYSTEM_DELETE = 'filesystem.delete',
    FILESYSTEM_LIST = 'filesystem.list',
    FILESYSTEM_SYMLINK = 'filesystem.symlink',
    FILESYSTEM_CHMOD = 'filesystem.chmod',
    FILESYSTEM_CHOWN = 'filesystem.chown',

    // Execution capabilities
    EXECUTION_SHELL = 'execution.shell',
    EXECUTION_SUBPROCESS = 'execution.subprocess',
    EXECUTION_SCRIPT = 'execution.script',
    EXECUTION_INTERACTIVE = 'execution.interactive',

    // Network capabilities
    NETWORK_HTTP_FETCH = 'network.http_fetch',
    NETWORK_TCP_CONNECT = 'network.tcp_connect',
    NETWORK_UDP_SEND = 'network.udp_send',
    NETWORK_DNS_QUERY = 'network.dns_query',
    NETWORK_SOCKET_LISTEN = 'network.socket_listen',
    NETWORK_SEARCH = 'network.search',

    // System capabilities
    SYSTEM_ENV_READ = 'system.env_read',
    SYSTEM_ENV_WRITE = 'system.env_write',
    SYSTEM_PROCESS_LIST = 'system.process_list',
    SYSTEM_PROCESS_SIGNAL = 'system.process_signal',
    SYSTEM_RESOURCE_USAGE = 'system.resource_usage',
    SYSTEM_PRIVILEGE_ESCALATE = 'system.privilege_escalate',

    // Data capabilities
    DATA_MEMORY_READ = 'data.memory_read',
    DATA_MEMORY_WRITE = 'data.memory_write',
    DATA_SENSITIVE = 'data.sensitive',
    DATA_CLIPBOARD_READ = 'data.clipboard_read',
    DATA_CLIPBOARD_WRITE = 'data.clipboard_write',
    DATA_SCREENSHOT = 'data.screenshot',

    // IPC capabilities
    IPC_PIPE = 'ipc.pipe',
    IPC_SOCKET = 'ipc.socket',
    IPC_SHARED_MEMORY = 'ipc.shared_memory',
    IPC_MESSAGE_QUEUE = 'ipc.message_queue',
}

/**
 * High-risk capabilities requiring extra scrutiny
 */
export const HIGH_RISK_CAPABILITIES = new Set<Capability>([
    Capability.FILESYSTEM_SYMLINK,
    Capability.FILESYSTEM_DELETE,
    Capability.SYSTEM_PRIVILEGE_ESCALATE,
    Capability.NETWORK_SOCKET_LISTEN,
    Capability.DATA_SCREENSHOT,
    Capability.IPC_PIPE,
    Capability.EXECUTION_SHELL,
]);

/**
 * Tool-to-Capability mapping for gemini-cli tools
 */
export const TOOL_CAPABILITIES: Record<string, Capability[]> = {
    // File system tools
    list_directory: [Capability.FILESYSTEM_LIST],
    read_file: [Capability.FILESYSTEM_READ],
    write_file: [Capability.FILESYSTEM_WRITE],
    glob: [Capability.FILESYSTEM_LIST],
    search_file_content: [Capability.FILESYSTEM_READ],
    replace: [Capability.FILESYSTEM_WRITE],

    // Shell tools
    run_shell_command: [Capability.EXECUTION_SHELL],

    // Web tools
    web_fetch: [Capability.NETWORK_HTTP_FETCH],
    google_web_search: [Capability.NETWORK_SEARCH],

    // Memory tools
    save_memory: [Capability.DATA_MEMORY_WRITE],

    // Todo tools
    write_todos: [Capability.DATA_MEMORY_WRITE],
};

/**
 * Get capabilities required for a given tool
 */
export function getToolCapabilities(toolName: string): Capability[] {
    return TOOL_CAPABILITIES[toolName] || [];
}

/**
 * Check if a capability is high-risk
 */
export function isHighRisk(capability: Capability): boolean {
    return HIGH_RISK_CAPABILITIES.has(capability);
}

/**
 * Get all capabilities in a specific category
 */
export function getCapabilitiesByCategory(category: string): Capability[] {
    return Object.values(Capability).filter(cap => cap.startsWith(category + '.'));
}
