// Retire the original offline worker so an upgraded browser loads the connected app.
self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    await self.registration.unregister()
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    await Promise.all(windows.map(client => client.navigate(client.url)))
  })())
})
