const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('archiveDesktop', {
  version: '1.0.0'
});
