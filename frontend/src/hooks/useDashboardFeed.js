import { useEffect, useRef, useState, useCallback } from 'react';

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;

/**
 * Opens a WebSocket to /api/ws/feed and reconnects automatically on disconnect.
 *
 * Returns:
 *   latestEvent  – the most recent parsed event object, or null
 *   connected    – boolean indicating live connection
 */
export function useDashboardFeed() {
    const [latestEvent, setLatestEvent] = useState(null);
    const [connected, setConnected] = useState(false);
    const wsRef = useRef(null);
    const backoffRef = useRef(INITIAL_BACKOFF_MS);
    const unmountedRef = useRef(false);
    const retryTimer = useRef(null);

    const connect = useCallback(() => {
        if (unmountedRef.current) return;

        const token = localStorage.getItem('access_token');
        if (!token) return;

        const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const url = `${proto}://${window.location.host}/api/ws/feed?token=${encodeURIComponent(token)}`;

        const ws = new WebSocket(url);
        wsRef.current = ws;

        ws.onopen = () => {
            setConnected(true);
            backoffRef.current = INITIAL_BACKOFF_MS;
        };

        ws.onmessage = (e) => {
            try {
                const event = JSON.parse(e.data);
                if (event.type !== 'ping') {
                    setLatestEvent(event);
                }
            } catch {
                // ignore malformed frames
            }
        };

        ws.onclose = () => {
            setConnected(false);
            if (unmountedRef.current) return;
            retryTimer.current = setTimeout(() => {
                backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF_MS);
                connect();
            }, backoffRef.current);
        };

        ws.onerror = () => {
            ws.close();
        };
    }, []);

    useEffect(() => {
        unmountedRef.current = false;
        connect();
        return () => {
            unmountedRef.current = true;
            clearTimeout(retryTimer.current);
            if (wsRef.current) {
                wsRef.current.onclose = null; // suppress reconnect on intentional unmount
                wsRef.current.close();
            }
        };
    }, [connect]);

    return { latestEvent, connected };
}
