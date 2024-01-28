import { invoke } from '@tauri-apps/api/tauri'

export async function authenticate() {
  await invoke('plugin:cohdb|authenticate')
}
