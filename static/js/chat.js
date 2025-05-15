document.addEventListener('DOMContentLoaded', function() {
    const messageForm = document.getElementById('messageForm');
    const messageInput = document.getElementById('messageInput');
    const messageContainer = document.getElementById('messageContainer');
    const chatList = document.getElementById('chatList');
    const userList = document.getElementById('userList');
    const userSearchInput = document.getElementById('userSearchInput');
    const activeChatId = document.getElementById('activeChatId');
    const chatTitle = document.getElementById('chatTitle');
    const currentUsername = document.getElementById('currentUsername');
    const newChatModal = new bootstrap.Modal(document.getElementById('newChatModal'));

    // Initialize
    let lastMessageCount = 0;
    let activeChat = activeChatId.value;
    let lastMessageId = 0;
    let windowHasFocus = true;
    let notificationsEnabled = false;
    
    // Initialize notifications
    initNotifications();
    
    fetchMessages();
    loadChatRooms();
    const messagePollingInterval = setInterval(fetchMessages, 3000);
    const chatPollingInterval = setInterval(loadChatRooms, 10000);
   
    
    
    // Check if window has focus
    window.addEventListener('focus', function() {
        windowHasFocus = true;
    });
    
    window.addEventListener('blur', function() {
        windowHasFocus = false;
    });
    
    // Initialize browser notifications
    function initNotifications() {
        // Check if the browser supports notifications
        if (!('Notification' in window)) {
            console.log('This browser does not support notifications');
            return;
        }
        
        // Check if permission is already granted
        if (Notification.permission === 'granted') {
            notificationsEnabled = true;
        } else if (Notification.permission !== 'denied') {
            // Add a button to request notification permission
            const notifyBtn = document.createElement('button');
            notifyBtn.className = 'btn btn-sm btn-outline-secondary me-2';
            notifyBtn.innerHTML = '<i class="bi bi-bell"></i> Enable Notifications';
            notifyBtn.addEventListener('click', requestNotificationPermission);
            
            // Add the button to the header
            const headerBtns = document.querySelector('.card-header .d-flex.gap-2');
            headerBtns.prepend(notifyBtn);
        }
    }
    
    
    function requestNotificationPermission() {
        Notification.requestPermission().then(function(permission) {
            if (permission === 'granted') {
                notificationsEnabled = true;
                
                const notifyBtn = document.querySelector('.btn-outline-secondary');
                if (notifyBtn) {
                    notifyBtn.remove();
                }
                // Show a success notification
                showNotification('Chat Notifications', 'Notifications are now enabled!');
            }
        });
    }
    
    // Show a notification
    function showNotification(title, body) {
        if (notificationsEnabled && !windowHasFocus) {
            const notification = new Notification(title, {
                body: body,
                icon: '/static/favicon.ico' 
            });
            
            // Close the notification after 5 seconds
            setTimeout(function() {
                notification.close();
            }, 5000);
            
            // Focus the window when the notification is clicked
            notification.onclick = function() {
                window.focus();
                this.close();
            };
        }
    }
    
    // Chat list item click
    chatList.addEventListener('click', function(e) {
        const chatItem = e.target.closest('.list-group-item');
        if (chatItem) {
            const chatId = chatItem.dataset.chatId;
            if (chatId !== activeChat) {
                activeChat = chatId;
                activeChatId.value = chatId;

                // Chat delete button click
chatList.addEventListener('click', async function(e) {
    const deleteBtn = e.target.closest('.delete-chat-btn');
    if (deleteBtn) {
        e.stopPropagation();
        const chatId = deleteBtn.dataset.chatId;
        if (chatId !== "0" && confirm('Are you sure you want to delete this chat?')) {
            await deleteChat(chatId);
        }
    }
});

                // Update UI
                document.querySelectorAll('#chatList .list-group-item').forEach(item => {
                    item.classList.remove('active');
                });
                chatItem.classList.add('active');
                
                // Update chat title
                chatTitle.textContent = chatItem.querySelector('.fw-bold').textContent;
                
                // Fetch messages for selected chat
                fetchMessages();
                
                // Update URL without page reload
                const url = chatId ? `/chat/${chatId}` : '/';
                history.pushState({}, '', url);
            }
        }
    });

    // Message form submission
    messageForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const message = messageInput.value.trim();
        if (!message) return;

        try {
            const formData = new FormData();
            formData.append('message', message);
            if (activeChat) {
                formData.append('chat_id', activeChat);
            }

            const response = await fetch('/send', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                messageInput.value = '';
                await fetchMessages();
            } else {
                const data = await response.json();
                
                // Check if this is a blacklisted word error
                if (data.blacklisted_words && data.blacklisted_words.length > 0) {
                    // Create a nicer error message with the blacklisted words
                    const blockedWords = data.blacklisted_words.join('", "');
                    const errorMessage = `Your message contains inappropriate language: "${blockedWords}"`;
                    
                    // Add a message div to inform the user (will disappear after 5 seconds)
                    const errorDiv = document.createElement('div');
                    errorDiv.className = 'alert alert-danger mt-2 mb-2';
                    errorDiv.innerHTML = `<i class="bi bi-exclamation-triangle-fill"></i> ${errorMessage}`;
                    
                    // Insert before the message form
                    messageForm.parentNode.insertBefore(errorDiv, messageForm);
                    
                    // Remove after 5 seconds
                    setTimeout(() => {
                        errorDiv.remove();
                    }, 5000);
                } else {
                    // General error
                    alert(data.error || 'Failed to send message');
                }
            }
        } catch (error) {
            console.error('Error sending message:', error);
            alert('Failed to send message');
        }
    });

    // Load available users for new chat
    newChatModal._element.addEventListener('shown.bs.modal', loadUsers);

    // User search
    userSearchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const userItems = userList.querySelectorAll('.list-group-item');
        
        userItems.forEach(item => {
            const username = item.textContent.toLowerCase();
            if (username.includes(searchTerm)) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    });

    // Start chat with selected user
    userList.addEventListener('click', async function(e) {
        const userItem = e.target.closest('.list-group-item');
        if (userItem) {
            const userId = userItem.dataset.userId;
            try {
                const formData = new FormData();
                formData.append('user_id', userId);
                
                const response = await fetch('/api/chats/create', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (response.ok) {
                    // Close modal
                    newChatModal.hide();
                    
                    // Load chat rooms and select the new one
                    await loadChatRooms();
                    
                    // Set the new chat as active
                    activeChat = data.chat.id;
                    activeChatId.value = activeChat;
                    
                    // Update URL without page reload
                    const url = `/chat/${activeChat}`;
                    history.pushState({}, '', url);
                    
                    // Update chat title
                    chatTitle.textContent = data.chat.name;
                    
                    // Fetch messages for selected chat
                    fetchMessages();
                } else {
                    alert(data.error || 'Failed to create chat');
                }
            } catch (error) {
                console.error('Error creating chat:', error);
                alert('Failed to create chat');
            }
        }
    });

    let soundEnabled = false;


function enableSound() {
    soundEnabled = true;
    document.removeEventListener('click', enableSound);
    document.removeEventListener('keydown', enableSound);
}
document.addEventListener('click', enableSound);
document.addEventListener('keydown', enableSound);

async function fetchMessages() {
    try {
        let url = '/messages';
        if (activeChat) {
            url += `?chat_id=${activeChat}`;
        }
        
        const response = await fetch(url);
        if (response.ok) {
            const messages = await response.json();
            
            if (messages.length > 0) {
                const latestMessageId = messages[messages.length - 1].id;

                if (lastMessageId > 0 && latestMessageId > lastMessageId && !windowHasFocus) {
                    const newMessages = messages.filter(msg => msg.id > lastMessageId);
                    
                    newMessages.forEach(msg => {
                        if (msg.username !== currentUsername.textContent) {
                            const chatName = chatTitle.textContent;

                            // Show browser notification
                            showNotification(
                                `New message from ${msg.username}`,
                                `${chatName}: ${msg.content}`
                            );

                            // Play notification sound
                            if (soundEnabled) {
                                const audio = new Audio('/static/sounds/notification.mp3');
                                audio.play().catch(err => {
                                    console.warn("Sound blocked or failed to play:", err);
                                });
                            }
                        }
                    });
                }

                lastMessageId = latestMessageId;
            }

            if (messages.length !== lastMessageCount) {
                updateMessages(messages);
                lastMessageCount = messages.length;
            }
        }
    } catch (error) {
        console.error('Error fetching messages:', error);
    }
}                   
    async function loadChatRooms() {
        try {
            const response = await fetch('/api/chats');
            if (response.ok) {
                const chats = await response.json();
                
                // Update chat list but keep the global chat
                const globalChatItem = chatList.querySelector('[data-chat-id=""]');
                const activeChatItem = chatList.querySelector('.active');
                const activeChatIdValue = activeChatItem ? activeChatItem.dataset.chatId : '';
                
                // Keep only the global chat item
                chatList.innerHTML = '';
                chatList.appendChild(globalChatItem);
                
                // Add the chat rooms
                chats.forEach(chat => {
                    const otherUsers = chat.participants
                        .filter(p => p.username !== currentUsername.textContent)
                        .map(p => p.username)
                        .join(', ');
                    
                    const chatItem = document.createElement('li');
                    chatItem.className = `list-group-item d-flex justify-content-between align-items-center
                                        ${chat.id == activeChatIdValue ? 'active' : ''}`;
                    chatItem.dataset.chatId = chat.id;
                   chatItem.innerHTML = `
    <div class="d-flex justify-content-between align-items-center w-100">
        <div>
            <div class="fw-bold">${chat.name}</div>
            <small class="text-muted">${otherUsers}</small>
        </div>
        ${chat.id !== 0 ? `
            <button class="btn btn-sm btn-danger ms-2 delete-chat-btn" data-chat-id="${chat.id}">
                <i class="bi bi-trash"></i>
            </button>` : ''
        }
    </div>
`;

                    chatList.appendChild(chatItem);
                });
            }
        } catch (error) {
            console.error('Error loading chat rooms:', error);
        }
    }

    async function loadUsers() {
        try {
            const response = await fetch('/api/users');
            if (response.ok) {
                const users = await response.json();
                
                if (users.length === 0) {
                    userList.innerHTML = `
                        <div class="text-center text-muted p-3">
                            <small>No online users available</small>
                        </div>
                    `;
                    return;
                }
                
                userList.innerHTML = '';
                users.forEach(user => {
                    const userItem = document.createElement('div');
                    userItem.className = 'list-group-item';
                    userItem.dataset.userId = user.id;
                    
                    const initial = user.username.charAt(0).toUpperCase();
                    userItem.innerHTML = `
                        <div class="user-item">
                            <div class="user-avatar">${initial}</div>
                            <div>${user.username}</div>
                            <div class="online-indicator"></div>
                        </div>
                    `;
                    userList.appendChild(userItem);
                });
            }
        } catch (error) {
            console.error('Error loading users:', error);
            userList.innerHTML = `
                <div class="text-center text-muted p-3">
                    <small>Failed to load users</small>
                </div>
            `;
        }
    }
let lastSeenMessageIds = new Set();
let isFirstLoad = true;

function updateMessages(messages) {
    const wasAtBottom = isAtBottom();
    const newIds = new Set(messages.map(m => m.id));

    // Remove messages that are no longer present
    lastSeenMessageIds.forEach(id => {
        if (!newIds.has(id)) lastSeenMessageIds.delete(id);
    });

    messageContainer.innerHTML = '';

    if (messages.length === 0) {
        messageContainer.innerHTML = `
            <div class="text-center text-muted mb-3">
                <small>No messages yet. Be the first to send a message!</small>
            </div>
        `;
        return;
    }

    messages.forEach(message => {
        const isNew = !lastSeenMessageIds.has(message.id);
        const messageElement = createMessageElement(message, isFirstLoad || isNew);
        messageContainer.appendChild(messageElement);
        lastSeenMessageIds.add(message.id);
    });

    if (wasAtBottom) scrollToBottom();
    isFirstLoad = false;
}

function createMessageElement(message, animate = false) {
    const div = document.createElement('div');
    const isOwnMessage = message.username === currentUsername.textContent;
    div.className = `message ${isOwnMessage ? 'own' : 'other'}`;

    if (animate) {
        div.classList.add('pop-in');
    }

    div.dataset.messageId = message.id;

    const isAdmin = document.body.dataset.isAdmin?.toLowerCase() === 'true';
    const adminControls = isAdmin ? `
        <div class="admin-controls">
            <button class="btn btn-sm btn-danger delete-message" onclick="deleteMessage(${message.id}, event)">
                <i class="bi bi-trash"></i> Delete Message
            </button>
        </div>` : '';

    div.innerHTML = `
        <div class="message-bubble">
            ${!isOwnMessage ? `<div class="message-username">${message.username}</div>` : ''}
            ${message.content}
        </div>
        <div class="message-meta">
            <span class="message-author">${message.username}</span> • ${message.timestamp}
        </div>
        ${adminControls}
    `;

    return div;
}

    function isAtBottom() {
        const threshold = 100;
        return (messageContainer.scrollHeight - messageContainer.scrollTop - messageContainer.clientHeight) < threshold;
    }

    function scrollToBottom() {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }

    // Set user as offline before closing tab
    window.addEventListener('beforeunload', function() {
        navigator.sendBeacon('/api/user/offline');
    });
});

// Admin function to delete messages
function deleteMessage(messageId, event) {
    if (!confirm('Are you sure you want to delete this message?')) {
        return;
    }
    
    event.preventDefault();
    
    fetch(`/admin/delete-message/${messageId}`, {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove the message element
            const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
            if (messageElement) {
                messageElement.remove();
            }
        } else {
            alert(data.error || 'Failed to delete message');
        }
    })
    .catch(error => {
        console.error('Error deleting message:', error);
        alert('Failed to delete message');
    });
}

async function deleteChat(chatId) {
    try {
        const response = await fetch(`/api/chats/delete/${chatId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            await loadChatRooms();

            // Reset active chat if it was deleted
            if (activeChat === chatId) {
                activeChat = '';
                activeChatId.value = '';
                chatTitle.textContent = 'Select a Chat';
                messageContainer.innerHTML = '';
            }
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to delete chat');
        }
    } catch (error) {
        console.error('Error deleting chat:', error);
        alert('Failed to delete chat');
    }
}


  document.addEventListener('DOMContentLoaded', () => {
    const konamiCode = [
      'ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown',
      'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight',
      'b', 'a'
    ];

    let inputBuffer = [];

    const k0nami = () => {
      document.body.classList.add('inverted-colors');

      const shakeInterval = setInterval(() => {
        document.body.classList.add('shake');
        setTimeout(() => document.body.classList.remove('shake'), 300);
      }, 400);

      window.addEventListener('beforeunload', () => {
        clearInterval(shakeInterval);
      });
    };

    const showConfirmation = () => {
      const popup = document.createElement('div');
      popup.style.position = 'fixed';
      popup.style.top = '0';
      popup.style.left = '0';
      popup.style.width = '100%';
      popup.style.height = '100%';
      popup.style.background = 'rgba(0,0,0,0.8)';
      popup.style.color = 'white';
      popup.style.display = 'flex';
      popup.style.alignItems = 'center';
      popup.style.justifyContent = 'center';
      popup.style.zIndex = '9999';

      const box = document.createElement('div');
      box.style.background = '#222';
      box.style.padding = '2rem';
      box.style.borderRadius = '1rem';
      box.style.textAlign = 'center';

      box.innerHTML = `
        <p style="margin-bottom: 1rem;">Warning<br>
        Continue only if you are not sensitive to motion or flashing lights. If you would like to cancel, please restart your client.</p>
        <button id="confirmKonami" style="padding: 0.5rem 1rem; font-size: 1rem;">Continue</button>
      `;

      popup.appendChild(box);
      document.body.appendChild(popup);

      document.getElementById('confirmKonami').addEventListener('click', () => {
        popup.remove();
        k0nami();
      });
    };

    document.addEventListener('keydown', (e) => {
      inputBuffer.push(e.key);
      if (inputBuffer.length > konamiCode.length) {
        inputBuffer.shift();
      }

      if (konamiCode.every((key, i) => inputBuffer[i] === key)) {
        showConfirmation();
      }
    });
  });

