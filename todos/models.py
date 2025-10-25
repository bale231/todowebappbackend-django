from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.db import models

class ListCategory(models.Model):
    """Categoria per raggruppare le liste"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="list_categories")
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']
        unique_together = ['user', 'name']

    def __str__(self):
        return f"{self.name} ({self.user.username})"

class Category(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="categories")
    name = models.CharField(max_length=50)
    color = models.CharField(max_length=20, default="blue")
    created_at = models.DateTimeField(auto_now_add=True)
    sort_order = models.CharField(max_length=20, default="created")
    category = models.ForeignKey(ListCategory, on_delete=models.SET_NULL, null=True, blank=True, related_name="lists")

class Todo(models.Model):
    title = models.CharField(max_length=255)
    completed = models.BooleanField(default=False)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True, blank=True)
    order = models.PositiveIntegerField(default=0)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    lists_sort_order = models.CharField(
        max_length=20,
        choices=[("created","Più recente"),("alphabetical","Alfabetico"),("complete","Per completezza")],
        default="created"
    )
    category_sort_alpha = models.BooleanField(default=False)
    profile_picture = models.ImageField(upload_to="profile_pics/", blank=True, null=True)
    theme = models.CharField(max_length=10, default="light")
    email_verified = models.BooleanField(default=False)
    push_notifications_enabled = models.BooleanField(default=True)
    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    bio = models.TextField(max_length=500, blank=True, null=True)
    fcm_token = models.TextField(blank=True, null=True)
    selected_category = models.ForeignKey(
        'ListCategory',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='selected_by_profiles'
    )

    def __str__(self):
        return f"Profilo di {self.user.username}"

    def get_full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.user.username

class Notification(models.Model):
    TYPE_CHOICES = [
        ('update_normal', 'Update Normal'),
        ('update_important', 'Important Update'),
        ('friend_request', 'Friend Request'),
        ('list_modified', 'List Modified'),
        ('general', 'General'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    from_user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='sent_notifications')
    list_name = models.CharField(max_length=200, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.title}"



class FriendRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'In attesa'),
        ('accepted', 'Accettata'),
        ('rejected', 'Rifiutata'),
    ]

    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_friend_requests')
    to_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_friend_requests')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['from_user', 'to_user']
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.from_user.username} -> {self.to_user.username} ({self.status})"


class Friendship(models.Model):
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friendships_initiated')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friendships_received')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user1', 'user2']
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user1.username} ↔ {self.user2.username}"

    @classmethod
    def are_friends(cls, user1, user2):
        """Controlla se due utenti sono amici"""
        return cls.objects.filter(
            models.Q(user1=user1, user2=user2) |
            models.Q(user1=user2, user2=user1)
        ).exists()

    @classmethod
    def get_friends(cls, user):
        """Ottiene tutti gli amici di un utente"""
        friendships = cls.objects.filter(
            models.Q(user1=user) | models.Q(user2=user)
        )
        friends = []
        for friendship in friendships:
            friend = friendship.user2 if friendship.user1 == user else friendship.user1
            friends.append(friend)
        return friends


class SharedList(models.Model):
    """Condivisione di una lista (Category) con un utente"""
    list = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='shares')
    shared_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='lists_shared_by')
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, related_name='lists_shared_with')
    can_edit = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['list', 'shared_with']
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.list.name} condivisa da {self.shared_by.username} con {self.shared_with.username}"


class SharedCategory(models.Model):
    """Condivisione di una categoria (ListCategory) con un utente"""
    category = models.ForeignKey(ListCategory, on_delete=models.CASCADE, related_name='shares')
    shared_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='categories_shared_by')
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, related_name='categories_shared_with')
    can_edit = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['category', 'shared_with']
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.category.name} condivisa da {self.shared_by.username} con {self.shared_with.username}"


# Segnale per creare automaticamente il profilo quando viene creato un nuovo utente
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    try:
        instance.profile.save()
    except Profile.DoesNotExist:
        Profile.objects.create(user=instance)
