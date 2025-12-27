export type LinuxKeyringBackend = 'gnome' | 'kwallet' | 'basic';
export declare function getLinuxChromeSafeStoragePassword(options?: {
    backend?: LinuxKeyringBackend;
}): Promise<{
    password: string;
    warnings: string[];
}>;
//# sourceMappingURL=linuxKeyring.d.ts.map