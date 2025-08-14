import Java from 'frida-java-bridge';

Java.perform(() => {
    const FLAG_SECURE = 0x2000;
    const Window = Java.use('android.view.Window');
    const MO = Java.use('org.telegram.messenger.MessageObject');
    const SD = Java.use('org.telegram.ui.SecretMediaViewer$SecretDeleteTimer');
    const MC = Java.use('org.telegram.messenger.MessagesController');
    const MS = Java.use('org.telegram.messenger.MessagesStorage');
    const SCH = Java.use('org.telegram.messenger.SecretChatHelper');
    
    let isUserAction = false;
    
    // Screenshot bypass for secret chats
    Window.addFlags.implementation = function(f: number) {
        this.addFlags(f & ~FLAG_SECURE);
    };
    
    Window.setFlags.implementation = function(f: number, m: number) {
        this.setFlags(f & ~FLAG_SECURE, m & ~FLAG_SECURE);
    };
    
    // Convert only INCOMING disappearing media to normal
    MO.$init.overloads.forEach((c: any) => {
        c.implementation = function(...args: any[]) {
            const r = c.apply(this, args);
            try {
                if ((this.isPhoto() || this.isVideo() || this.isGif() || this.isRoundVideo() || 
                     this.isVoice() || this.isMusic() || this.isDocument()) && !this.isOutOwner()) {
                    const msg = this.messageOwner.value;
                    const media = this.getMedia(msg);
                    
                    msg.ttl.value = 0;
                    msg.destroyTime.value = 0;
                    if (media && media.ttl_seconds) {
                        media.ttl_seconds.value = 0;
                    }
                }
            } catch(e) {}
            return r;
        };
    });
    
    MO.needDrawBluredPreview.implementation = function() { return false; };
    SD.setDestroyTime.implementation = function(d: number, t: number, v: boolean) {};
    
    // Track when YOU delete
    MC.deleteMessages.overloads.forEach((overload: any) => {
        overload.implementation = function(...args: any[]) {
            isUserAction = true;
            const result = overload.apply(this, args);
            setTimeout(() => { isUserAction = false; }, 500);
            return result;
        };
    });
    
    // Only block if not user action
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
    
    // Only filter updates when not user action
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
});
