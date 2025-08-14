import Java from 'frida-java-bridge';
// The above is needed for frida 17
Java.perform(() => {
    const FLAG_SECURE = 0x2000;
    const Window = Java.use('android.view.Window');
    const MO = Java.use('org.telegram.messenger.MessageObject');
    const SD = Java.use('org.telegram.ui.SecretMediaViewer$SecretDeleteTimer');
    const MC = Java.use('org.telegram.messenger.MessagesController');
    
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
    
    // Block deletion methods
    MC.markDialogMessageAsDeleted.implementation = function(dialogId: any, messageIds: any) {};
    MC.deleteMessages.overloads.forEach((overload: any) => {
        overload.implementation = function(...args: any[]) {};
    });
    
    // Minimal loop - only check for TL_updateReadMessagesContents
    MC.processUpdateArray.overload('java.util.ArrayList', 'java.util.ArrayList', 'java.util.ArrayList', 'boolean', 'int')
        .implementation = function(updates: any, users: any, chats: any, fromGetDiff: boolean, date: number) {
            // Single-purpose loop: remove view-once read updates
            for (let i = updates.size() - 1; i >= 0; i--) {
                if (updates.get(i).getClass().getName().endsWith('TL_updateReadMessagesContents')) {
                    updates.remove(i);
                }
            }
            
            return this.processUpdateArray(updates, users, chats, fromGetDiff, date);
        };
});
