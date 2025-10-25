from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import Todo, Category, Profile, Notification, FriendRequest, Friendship

# Inline per Profile nell'admin User
class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profilo'
    fk_name = 'user'

# Estendi UserAdmin per includere Profile
class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'get_full_name')
    
    def get_full_name(self, obj):
        if hasattr(obj, 'profile'):
            return obj.profile.get_full_name()
        return obj.username
    get_full_name.short_description = 'Nome completo'

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

# Register models
admin.site.register(Todo)
admin.site.register(Category)

# Profile Admin
@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'get_full_name', 'theme', 'email_verified', 'push_notifications_enabled')
    list_filter = ('theme', 'email_verified', 'push_notifications_enabled')
    search_fields = ('user__username', 'first_name', 'last_name')
    
    def get_full_name(self, obj):
        return obj.get_full_name()
    get_full_name.short_description = 'Nome completo'

# Notification Admin (con broadcast)
@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'type', 'title', 'read', 'created_at', 'from_user']
    list_filter = ('type', 'read', 'created_at')
    search_fields = ('user__username', 'title', 'message')
    ordering = ('-created_at',)
    actions = ['broadcast_to_all']
    
    def broadcast_to_all(self, request, queryset):
        if queryset.count() != 1:
            self.message_user(request, "Seleziona UNA sola notifica da inviare", level='error')
            return
        template = queryset.first()
        users = User.objects.all()
        for user in users:
            Notification.objects.create(
                user=user,
                type=template.type,
                title=template.title,
                message=template.message
            )
        self.message_user(request, f"Notifica inviata a {users.count()} utenti")
    broadcast_to_all.short_description = "Invia a tutti gli utenti"

# FriendRequest Admin
@admin.register(FriendRequest)
class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ('from_user', 'to_user', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at')
    search_fields = ('from_user__username', 'to_user__username')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')

# Friendship Admin
@admin.register(Friendship)
class FriendshipAdmin(admin.ModelAdmin):
    list_display = ('user1', 'user2', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user1__username', 'user2__username')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)