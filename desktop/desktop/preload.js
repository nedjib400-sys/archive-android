const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('archiveDesktop', {
  connect: (address) => ipcRenderer.invoke('connect-server', address)
});
