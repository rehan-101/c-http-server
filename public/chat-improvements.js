/**
 * Frontend Security & Performance Improvements Module
 * 
 * This module provides:
 * - Secure token storage using HttpOnly cookie approach
 * - XSS prevention utilities
 * - Virtual message list implementation
 * - Message pagination
 * - Offline message queue with IndexedDB
 * - Performance optimizations
 */

// ============================================================================
// 1. SECURE TOKEN MANAGEMENT
// ============================================================================

class SecureTokenManager {
    constructor() {
        this.COOKIE_NAME = 'auth_token';
        this.COOKIE_MAX_AGE = 3600; // 1 hour
    }

    /**
     * Store token via HTTP-only cookie (server-side)
     * Client should NOT directly set this - server should set via Set-Cookie header
     * This is informational for secure implementation
     */
    static setTokenSecurely(token) {
        // DO NOT use localStorage for tokens!
        // Instead, server should return: Set-Cookie: auth_token=<JWT>; HttpOnly; Secure; SameSite=Strict
        console.warn('Tokens should be stored via HttpOnly cookies set by server, not localStorage');
    }

    /**
     * Get token from cookie (will be automatically included by browser)
     */
    static getTokenFromCookie() {
        const match = document.cookie.match(`${this.COOKIE_NAME}=([^;]+)`);
        return match ? match[1] : null;
    }

    /**
     * Clear token from cookie
     */
    static clearToken() {
        document.cookie = `${this.COOKIE_NAME}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict;`;
        localStorage.removeItem('username');
        localStorage.removeItem('userId');
    }

    /**
     * Check if token exists
     */
    static hasToken() {
        return !!this.getTokenFromCookie();
    }
}

// ============================================================================
// 2. XSS PREVENTION & HTML ESCAPING
// ============================================================================

class XSSPrevention {
    /**
     * Escape HTML special characters
     */
    static escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    /**
     * Create safe DOM element from user input
     */
    static createSafeTextElement(tag, text) {
        const element = document.createElement(tag);
        element.textContent = text; // textContent is XSS-safe
        return element;
    }

    /**
     * Sanitize message for display (allow basic formatting only)
     */
    static sanitizeMessage(message) {
        // Remove any HTML/script tags
        let sanitized = message
            .replace(/<script[^>]*>.*?<\/script>/gi, '')
            .replace(/<[^>]+>/g, '');

        // Escape remaining special characters
        return this.escapeHtml(sanitized);
    }

    /**
     * Validate message before sending
     */
    static validateMessage(message) {
        if (!message || typeof message !== 'string') {
            return { valid: false, error: 'Message must be a string' };
        }

        if (message.length === 0) {
            return { valid: false, error: 'Message cannot be empty' };
        }

        if (message.length > 4096) {
            return { valid: false, error: 'Message too long (max 4096 chars)' };
        }

        // Check for valid UTF-8 (basic check)
        try {
            new TextEncoder().encode(message);
        } catch (e) {
            return { valid: false, error: 'Invalid character encoding' };
        }

        return { valid: true };
    }
}

// ============================================================================
// 3. VIRTUAL MESSAGE LIST (PERFORMANCE)
// ============================================================================

class VirtualMessageList {
    constructor(containerSelector, options = {}) {
        this.container = document.querySelector(containerSelector);
        this.itemHeight = options.itemHeight || 70;
        this.bufferSize = options.bufferSize || 5;
        this.messages = [];
        this.visibleRange = { start: 0, end: 0 };
        this.scrollTop = 0;

        // For throttling scroll events
        this.scrollTimeout = null;
        this.throttleDelay = 50;

        this.setupScrollListener();
    }

    setupScrollListener() {
        this.container.addEventListener('scroll', () => this.handleScroll(), { passive: true });
    }

    handleScroll() {
        clearTimeout(this.scrollTimeout);
        this.scrollTimeout = setTimeout(() => {
            this.updateVisibleRange();
        }, this.throttleDelay);
    }

    updateVisibleRange() {
        const { scrollTop, clientHeight } = this.container;
        const start = Math.max(0, Math.floor(scrollTop / this.itemHeight) - this.bufferSize);
        const end = Math.min(
            this.messages.length,
            Math.ceil((scrollTop + clientHeight) / this.itemHeight) + this.bufferSize
        );

        if (start !== this.visibleRange.start || end !== this.visibleRange.end) {
            this.visibleRange = { start, end };
            this.render();
        }
    }

    setMessages(messages) {
        this.messages = messages;
        this.updateVisibleRange();
    }

    addMessages(newMessages) {
        this.messages.push(...newMessages);
        this.updateVisibleRange();
    }

    prependMessages(newMessages) {
        this.messages.unshift(...newMessages);
        this.updateVisibleRange();
    }

    render() {
        const fragment = document.createDocumentFragment();
        const { start, end } = this.visibleRange;

        // Top spacer
        if (start > 0) {
            const topSpacer = document.createElement('div');
            topSpacer.style.height = (start * this.itemHeight) + 'px';
            fragment.appendChild(topSpacer);
        }

        // Visible items
        for (let i = start; i < end && i < this.messages.length; i++) {
            const itemElement = this.renderItem(this.messages[i], i);
            fragment.appendChild(itemElement);
        }

        // Bottom spacer
        if (end < this.messages.length) {
            const bottomSpacer = document.createElement('div');
            bottomSpacer.style.height = ((this.messages.length - end) * this.itemHeight) + 'px';
            fragment.appendChild(bottomSpacer);
        }

        // Replace container content
        this.container.innerHTML = '';
        this.container.appendChild(fragment);
    }

    renderItem(message, index) {
        const wrapper = document.createElement('div');
        wrapper.className = 'message-virtual-item';
        wrapper.style.minHeight = this.itemHeight + 'px';

        // Create message element safely
        const msgEl = document.createElement('div');
        msgEl.className = 'message-bubble';

        const usernameEl = XSSPrevention.createSafeTextElement('strong', message.username);
        const textEl = XSSPrevention.createSafeTextElement('p', message.text);

        msgEl.appendChild(usernameEl);
        msgEl.appendChild(textEl);
        wrapper.appendChild(msgEl);

        return wrapper;
    }

    scrollToBottom(smooth = true) {
        this.container.scrollTo({
            top: this.container.scrollHeight,
            behavior: smooth ? 'smooth' : 'auto'
        });
    }

    scrollToMessage(index, smooth = true) {
        const position = index * this.itemHeight;
        this.container.scrollTo({
            top: position,
            behavior: smooth ? 'smooth' : 'auto'
        });
    }

    getVisibleCount() {
        return this.visibleRange.end - this.visibleRange.start;
    }

    getTotalCount() {
        return this.messages.length;
    }
}

// ============================================================================
// 4. MESSAGE PAGINATION
// ============================================================================

class MessagePaginator {
    constructor(options = {}) {
        this.pageSize = options.pageSize || 20;
        this.currentPage = 0;
        this.hasMore = true;
        this.isLoading = false;
    }

    async loadPage(pageNumber, fetchFunction) {
        if (this.isLoading) return null;

        this.isLoading = true;
        try {
            const offset = pageNumber * this.pageSize;
            const response = await fetchFunction(this.pageSize, offset);

            this.hasMore = response.hasMore ?? (response.messages.length === this.pageSize);
            this.currentPage = pageNumber;

            return response.messages;
        } finally {
            this.isLoading = false;
        }
    }

    async loadNext(fetchFunction) {
        return this.loadPage(this.currentPage + 1, fetchFunction);
    }

    async loadPrevious(fetchFunction) {
        if (this.currentPage === 0) return null;
        return this.loadPage(this.currentPage - 1, fetchFunction);
    }

    reset() {
        this.currentPage = 0;
        this.hasMore = true;
        this.isLoading = false;
    }
}

// ============================================================================
// 5. OFFLINE MESSAGE QUEUE (IndexedDB)
// ============================================================================

class OfflineMessageQueue {
    constructor(dbName = 'ChatAppDB', storeName = 'messageQueue') {
        this.dbName = dbName;
        this.storeName = storeName;
        this.db = null;
        this.initialized = false;
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, 1);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                this.initialized = true;
                resolve();
            };

            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName, { keyPath: 'id', autoIncrement: true });
                }
            };
        });
    }

    async addMessage(message) {
        if (!this.initialized) await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction([this.storeName], 'readwrite');
            const store = tx.objectStore(this.storeName);

            const record = {
                ...message,
                timestamp: Date.now(),
                retries: 0,
                pending: true
            };

            const request = store.add(record);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async getMessages() {
        if (!this.initialized) await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction([this.storeName], 'readonly');
            const store = tx.objectStore(this.storeName);
            const request = store.getAll();

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async removeMessage(id) {
        if (!this.initialized) await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction([this.storeName], 'readwrite');
            const store = tx.objectStore(this.storeName);
            const request = store.delete(id);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    }

    async clearAll() {
        if (!this.initialized) await this.init();

        return new Promise((resolve, reject) => {
            const tx = this.db.transaction([this.storeName], 'readwrite');
            const store = tx.objectStore(this.storeName);
            const request = store.clear();

            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve();
        });
    }
}

// ============================================================================
// 6. IMPROVED WEBSOCKET HANDLER
// ============================================================================

class ImprovedWebSocketClient {
    constructor(url, options = {}) {
        this.url = url;
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = options.maxReconnectAttempts || 10;
        this.baseReconnectDelay = options.baseReconnectDelay || 1000;
        this.maxReconnectDelay = options.maxReconnectDelay || 30000;
        this.messageQueue = [];
        this.isConnecting = false;
        this.isConnected = false;
        this.messageListeners = {};
        this.offlineQueue = new OfflineMessageQueue();
    }

    /**
     * Connect to WebSocket with auto-reconnect
     */
    async connect(token) {
        if (this.isConnecting || this.isConnected) return;

        this.isConnecting = true;

        try {
            await this.offlineQueue.init();

            this.ws = new WebSocket(this.url);

            this.ws.onopen = () => {
                console.log('[WebSocket] Connected');
                this.isConnected = true;
                this.isConnecting = false;
                this.reconnectAttempts = 0;

                // Send auth message first
                this.send({
                    type: 'auth',
                    token: token
                });

                // Flush queued messages
                this.flushMessageQueue();

                // Flush offline queue
                this.flushOfflineQueue();

                this.emit('connected');
            };

            this.ws.onmessage = (event) => {
                this.handleMessage(event.data);
            };

            this.ws.onerror = (error) => {
                console.error('[WebSocket] Error:', error);
                this.emit('error', error);
            };

            this.ws.onclose = () => {
                console.log('[WebSocket] Disconnected');
                this.isConnected = false;
                this.isConnecting = false;
                this.emit('disconnected');

                // Attempt to reconnect
                this.attemptReconnect(token);
            };
        } catch (error) {
            console.error('[WebSocket] Connection error:', error);
            this.isConnecting = false;
            this.emit('error', error);
            this.attemptReconnect(token);
        }
    }

    send(message) {
        if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        } else {
            // Queue message for later
            this.messageQueue.push(message);
        }
    }

    async sendMessage(chatId, text, mentions = []) {
        const msgId = this.generateId();
        const message = {
            type: 'message',
            id: msgId,
            chatId,
            text,
            mentions,
            timestamp: Date.now()
        };

        // Add to offline queue first
        await this.offlineQueue.addMessage(message);

        // Try to send immediately
        this.send(message);

        return msgId;
    }

    handleMessage(data) {
        try {
            const message = JSON.parse(data);
            const handler = this.messageListeners[message.type];

            if (handler) {
                handler(message);
            }

            this.emit(`message:${message.type}`, message);
        } catch (error) {
            console.error('[WebSocket] Message parsing error:', error);
        }
    }

    on(type, handler) {
        this.messageListeners[type] = handler;
    }

    once(type, handler) {
        const wrapper = (message) => {
            handler(message);
            delete this.messageListeners[type];
        };
        this.messageListeners[type] = wrapper;
    }

    emit(event, data) {
        const event_obj = new CustomEvent(event, { detail: data });
        window.dispatchEvent(event_obj);
    }

    flushMessageQueue() {
        while (this.messageQueue.length > 0 && this.isConnected) {
            const msg = this.messageQueue.shift();
            this.send(msg);
        }
    }

    async flushOfflineQueue() {
        try {
            const messages = await this.offlineQueue.getMessages();

            for (const msg of messages) {
                // Resend message
                this.send({
                    type: 'message',
                    ...msg
                });

                // Remove from queue after successful send
                await this.offlineQueue.removeMessage(msg.id);
            }
        } catch (error) {
            console.error('[OfflineQueue] Error flushing queue:', error);
        }
    }

    attemptReconnect(token) {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('[WebSocket] Max reconnect attempts reached');
            this.emit('maxReconnectAttemptsReached');
            return;
        }

        this.reconnectAttempts++;
        const delay = Math.min(
            this.baseReconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
            this.maxReconnectDelay
        );

        console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

        setTimeout(() => {
            this.connect(token);
        }, delay);
    }

    disconnect() {
        if (this.ws) {
            this.ws.close(1000, 'Normal closure');
        }
    }

    generateId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    // ========================================================================
    // EXPORT FOR USE IN HTML
    // ========================================================================
}

window.ChatSecurity = {
    SecureTokenManager,
    XSSPrevention,
    VirtualMessageList,
    MessagePaginator,
    OfflineMessageQueue,
    ImprovedWebSocketClient
};
