import Java from 'frida-java-bridge';

Java.perform(() => {
    console.log("[*] Loading Complete Timer & One-Time Media Bypass...");
    
    const FLAG_SECURE = 0x2000;
    const Window = Java.use('android.view.Window');
    const MO = Java.use('org.telegram.messenger.MessageObject');
    const MC = Java.use('org.telegram.messenger.MessagesController');
    const MS = Java.use('org.telegram.messenger.MessagesStorage');
    const SCH = Java.use('org.telegram.messenger.SecretChatHelper');
    const PhotoViewer = Java.use('org.telegram.ui.PhotoViewer');
    
    let isUserAction = false;
    
    // Maps to track different types of disappearing messages
    const regularOneTimeMessages = new Map<number, {dialogId: number, ttl: number}>();
    const secretTimerMessages = new Map<number, {dialogId: number, ttl: number, randomId: number, isSecret: boolean}>();
    
    // ============================================
    // 1. SCREENSHOT BYPASS
    // ============================================
    
    Window.addFlags.implementation = function(f: number) {
        this.addFlags(f & ~FLAG_SECURE);
    };
    
    Window.setFlags.implementation = function(f: number, m: number) {
        this.setFlags(f & ~FLAG_SECURE, m & ~FLAG_SECURE);
    };
    
    // ============================================
    // 2. TRACK AND CONVERT DISAPPEARING MESSAGES
    // ============================================
    
    MO.$init.overloads.forEach((c: any) => {
        c.implementation = function(...args: any[]) {
            const r = c.apply(this, args);
            
            try {
                if (!this.isOutOwner()) {
                    const msg = this.messageOwner.value;
                    const messageId = this.getId();
                    const dialogId = this.getDialogId();
                    const media = this.getMedia(msg);
                    
                    // Check if it's a secret chat
                    const isSecretChat = messageId < 0 || (dialogId >> 32) > 0;
                    
                    // Get TTL values
                    const originalTTL = msg.ttl ? msg.ttl.value : 0;
                    const mediaTTL = media && media.ttl_seconds ? media.ttl_seconds.value : 0;
                    const destroyTime = msg.destroyTime ? msg.destroyTime.value : 0;
                    
                    // Check if already processed
                    const alreadyTracked = secretTimerMessages.has(messageId) || regularOneTimeMessages.has(messageId);
                    
                    if (!alreadyTracked) {
                        if (isSecretChat && (originalTTL > 0 || mediaTTL > 0 || destroyTime > 0)) {
                            // Secret chat message with timer
                            console.log(`[*] Secret chat message: ID=${messageId}, TTL=${originalTTL}`);
                            
                            secretTimerMessages.set(messageId, {
                                dialogId: dialogId,
                                ttl: originalTTL || mediaTTL || 1,
                                randomId: msg.random_id ? msg.random_id.value : 0,
                                isSecret: true
                            });
                            console.log(`[+] Tracked secret timer message`);
                        } else if ((originalTTL > 0 || mediaTTL > 0) && !isSecretChat) {
                            // Regular one-time message
                            console.log(`[+] Regular one-time message: ID=${messageId}, TTL=${originalTTL || mediaTTL}`);
                            
                            regularOneTimeMessages.set(messageId, {
                                dialogId: dialogId,
                                ttl: originalTTL || mediaTTL
                            });
                        }
                    }
                    
                    // Remove all TTLs to prevent deletion (do this every time)
                    if (originalTTL > 0 || mediaTTL > 0 || destroyTime > 0) {
                        if (msg.ttl) msg.ttl.value = 0;
                        if (msg.destroyTime) msg.destroyTime.value = 0;
                        if (media && media.ttl_seconds) media.ttl_seconds.value = 0;
                        
                        if (!alreadyTracked) {
                            console.log("[✓] Removed timer/TTL");
                        }
                    }
                }
            } catch(e) {
                console.log("[x] Error in MessageObject init: " + e);
            }
            
            return r;
        };
    });
    
    MO.needDrawBluredPreview.implementation = function() { return false; };
    
    // ============================================
    // 3. HOOK PHOTO VIEWER FOR BOTH TYPES
    // ============================================
    
    PhotoViewer.openPhoto.overloads.forEach((overload: any) => {
        overload.implementation = function(...args: any[]) {
            // Track if we've already processed this opening
            const processedKey = `${Date.now()}_open`;
            
            // Find MessageObject in arguments
            let messageObject: any = null;
            for (let i = 0; i < args.length && i < 5; i++) {
                if (args[i] && args[i].getClass) {
                    try {
                        const className = args[i].getClass().getName();
                        if (className.includes('MessageObject')) {
                            messageObject = args[i];
                            break;
                        }
                    } catch(e) {}
                }
            }
            
            // Execute original method
            const result = overload.apply(this, args);
            
            if (messageObject) {
                const messageId = messageObject.getId();
                const dialogId = messageObject.getDialogId();
                
                // Check if it's a regular one-time message
                if (regularOneTimeMessages.has(messageId)) {
                    const info = regularOneTimeMessages.get(messageId);
                    console.log(`[!] Opening one-time photo: ${messageId}`);
                    
                    // Send regular one-time acknowledgment
                    sendRegularOneTimeAck(messageId, info!.dialogId);
                    regularOneTimeMessages.delete(messageId);
                }
                // Check if it's a secret timer message
                else if (secretTimerMessages.has(messageId)) {
                    const info = secretTimerMessages.get(messageId);
                    console.log(`[!] Opening secret timer photo: ${messageId}`);
                    
                    // Mark as processing to avoid duplicate sends
                    const processingKey = `processing_${messageId}`;
                    if (!(globalThis as any)[processingKey]) {
                        (globalThis as any)[processingKey] = true;
                        
                        // Send secret chat acknowledgment with delay
                        setTimeout(() => {
                            sendSecretChatReadAck(messageId, dialogId, info!.randomId);
                            secretTimerMessages.delete(messageId);
                            delete (globalThis as any)[processingKey];
                        }, 100);
                    }
                }
            }
            
            return result;
        };
    });
    
    // ============================================
    // 4. SEND REGULAR ONE-TIME ACKNOWLEDGMENT
    // ============================================
    
    function sendRegularOneTimeAck(messageId: number, dialogId: number) {
        console.log(`[*] Sending one-time view acknowledgment for ${messageId}`);
        
        try {
            const MC = Java.use('org.telegram.messenger.MessagesController');
            const mcInstance = MC.getInstance(0);
            
            mcInstance.markMessageAsRead2(dialogId, messageId, null, 0, 0, false);
            console.log("[✓] Sent one-time acknowledgment");
        } catch(e) {
            console.log(`[x] Failed to send one-time ack: ${e}`);
        }
    }
    
    // ============================================
    // 5. SEND SECRET CHAT ACKNOWLEDGMENT
    // ============================================
    
    function sendSecretChatReadAck(messageId: number, dialogId: number, randomId: number) {
        console.log(`[*] Sending secret chat timer notification for ${messageId}`);
        
        try {
            const MC = Java.use('org.telegram.messenger.MessagesController');
            const mcInstance = MC.getInstance(0);
            const Integer = Java.use('java.lang.Integer');
            
            // Send read acknowledgment
            mcInstance.markMessageAsRead2(dialogId, messageId, null, 0, 0, false);
            
            // Get the actual encrypted chat
            try {
                const SCH = Java.use('org.telegram.messenger.SecretChatHelper');
                const schInstance = SCH.getInstance(0);
                const Long = Java.use('java.lang.Long');
                const ArrayList = Java.use('java.util.ArrayList');
                
                // Find actual chat ID from map
                let actualChatId: any = null;
                let encryptedChat: any = null;
                
                const encryptedChatsMap = mcInstance.encryptedChats.value;
                if (encryptedChatsMap && encryptedChatsMap.size() > 0) {
                    const keySet = encryptedChatsMap.keySet();
                    const iterator = keySet.iterator();
                    if (iterator.hasNext()) {
                        actualChatId = iterator.next(); // This is already an Integer object
                    }
                }
                
                if (actualChatId) {
                    // actualChatId is already an Integer object, use it directly
                    try {
                        encryptedChat = mcInstance.getEncryptedChat(actualChatId);
                    } catch(e) {
                        // If that fails, try converting to primitive first
                        try {
                            const chatIdValue = (actualChatId as any).intValue();
                            encryptedChat = mcInstance.getEncryptedChat(chatIdValue);
                        } catch(e2) {
                            console.log(`  Chat retrieval error: ${e2}`);
                        }
                    }
                    
                    if (encryptedChat && randomId !== 0) {
                        const randomIds = ArrayList.$new();
                        randomIds.add(Long.$new(randomId.toString()));
                        
                        schInstance.sendMessagesReadMessage(encryptedChat, randomIds, null);
                        console.log("[✓] Sent secret chat timer notification");
                        
                        // Removed sendScreenshotMessage - it was causing unwanted screenshot notifications
                    }
                }
            } catch(e) {
                console.log(`[x] Secret chat notification error: ${e}`);
            }
        } catch(e) {
            console.log(`[x] Failed to send secret ack: ${e}`);
        }
    }
    
    // ============================================
    // 6. BLOCK DELETION TIMER
    // ============================================
    
    try {
        const SD = Java.use('org.telegram.ui.SecretMediaViewer$SecretDeleteTimer');
        SD.setDestroyTime.implementation = function(d: number, t: number, v: boolean) {
            console.log("[!] Blocking destruction timer");
        };
    } catch(e) {}
    
    // ============================================
    // 7. BLOCK DELETION MESSAGES
    // ============================================
    
    MC.deleteMessages.overloads.forEach((overload: any) => {
        overload.implementation = function(...args: any[]) {
            isUserAction = true;
            const result = overload.apply(this, args);
            setTimeout(() => { isUserAction = false; }, 500);
            return result;
        };
    });
    
    MC.markDialogMessageAsDeleted.implementation = function(dialogId: any, messageIds: any) {
        if (isUserAction) return this.markDialogMessageAsDeleted(dialogId, messageIds);
    };
    
    MS.markMessagesAsDeleted.overloads.forEach((o: any) => {
        o.implementation = function(...args: any[]) {
            return isUserAction ? o.apply(this, args) : Java.use('java.util.ArrayList').$new();
        };
    });
    
    MS.markMessagesAsDeletedByRandoms.overloads.forEach((o: any) => {
        o.implementation = function(...args: any[]) {
            if (isUserAction) return o.apply(this, args);
        };
    });
    
    SCH['lambda$processDecryptedObject$12'].implementation = function(...args: any[]) {
        if (isUserAction) return this['lambda$processDecryptedObject$12'].apply(this, args);
    };
    
    MC.processUpdateArray.overload('java.util.ArrayList', 'java.util.ArrayList', 'java.util.ArrayList', 'boolean', 'int')
        .implementation = function(updates: any, users: any, chats: any, fromGetDiff: boolean, date: number) {
            if (!isUserAction) {
                for (let i = updates.size() - 1; i >= 0; i--) {
                    const className = updates.get(i).getClass().getName();
                    if (className.endsWith('TL_updateReadMessagesContents') ||
                        className.endsWith('TL_updateDeleteMessages') ||
                        className.endsWith('TL_updateDeleteChannelMessages') ||
                        className.endsWith('TL_updateChannelAvailableMessages')) {
                        updates.remove(i);
                    }
                }
            }
            return this.processUpdateArray(updates, users, chats, fromGetDiff, date);
        };
    
    // ============================================
    // 8. DEBUG HELPERS
    // ============================================
    
    (globalThis as any).inspectMessage = function(messageId: number) {
        console.log(`[DEBUG] Message ${messageId}:`);
        
        if (regularOneTimeMessages.has(messageId)) {
            const info = regularOneTimeMessages.get(messageId);
            console.log(`  Type: Regular one-time`);
            console.log(`  Dialog: ${info!.dialogId}, TTL: ${info!.ttl}`);
        } else if (secretTimerMessages.has(messageId)) {
            const info = secretTimerMessages.get(messageId);
            console.log(`  Type: Secret chat timer`);
            console.log(`  Dialog: ${info!.dialogId}, TTL: ${info!.ttl}`);
            console.log(`  RandomId: ${info!.randomId}`);
        } else {
            console.log(`  Not tracked`);
        }
    };
    
    console.log("[✓] Complete Timer & One-Time Media Bypass loaded!");
    console.log("[✓] Features enabled:");
    console.log("    - Screenshots in secret chats");
    console.log("    - One-time photos preserved (regular chats)");
    console.log("    - Timer messages preserved (secret chats)");
    console.log("    - Sender gets 'viewed' notification");
    console.log("[i] Debug: inspectMessage(messageId)");
});
