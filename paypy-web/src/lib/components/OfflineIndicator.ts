<!-- src/lib/components/OfflineIndicator.svelte -->
<script>
  import { onMount } from 'svelte';
  import { browser } from '$app/environment';
  import { writable } from 'svelte/store';
  
  const isOffline = writable(false);
  
  onMount(() => {
    if (!browser) return;
    
    // Set initial state
    $isOffline = !navigator.onLine;
    
    // Add event listeners for online/offline events
    const handleOffline = () => {
      $isOffline = true;
      console.log('App is offline');
    };
    
    const handleOnline = () => {
      $isOffline = false;
      console.log('App is online');
    };
    
    window.addEventListener('offline', handleOffline);
    window.addEventListener('online', handleOnline);
    
    return () => {
      window.removeEventListener('offline', handleOffline);
      window.removeEventListener('online', handleOnline);
    };
  });
</script>

{#if $isOffline}
  <div class="offline-indicator">
    You are currently offline. Some features may not be available.
  </div>
{/if}

<style>
  .offline-indicator {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background-color: #ff9800;
    color: white;
    padding: 8px 16px;
    text-align: center;
    z-index: 1000;
  }
</style>
