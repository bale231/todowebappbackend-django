from django.urls import path
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # --- ✅ Auth & Account (JWT) ---
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("mobile-login/", MobileLoginView.as_view(), name="mobile_login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("delete-account/", DeleteAccountView.as_view(), name="delete_account"),
    path("jwt-user/", JWTCurrentUserView.as_view(), name="jwt_user"),
    path("update-profile-jwt/", UpdateProfileJWTView.as_view(), name="update_profile_jwt"),
    path("update-theme/", UpdateThemeView.as_view(), name="update_theme"),
    path("send-verification-email/", SendEmailVerificationView.as_view(), name="send_verification_email"),
    path("verify-email/<uidb64>/<token>/", ConfirmEmailView.as_view(), name="verify_email"),
    path("reset-password/", SendResetPasswordEmailView.as_view(), name="send_reset_password"),
    path("reset-password/<uidb64>/<token>/", ResetPasswordConfirmView.as_view(), name="reset_password_confirm"),

    # --- ✅ JWT Token Management ---
    path("token/", EmailOrUsernameTokenView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # --- ✅ Liste ToDo (Categorie) ---
    path("lists/", CategoryListView.as_view(), name="category-list"),
    path("categories/", ListCategoryListView.as_view(), name="list-categories"),
    path("categories/<int:pk>/", ListCategoryDetailView.as_view(), name="list-category-detail"),
    path("categories/sort_preference/", CategorySortPreferenceView.as_view(), name="category-sort-preference"),
    path("categories/selected/", SelectedCategoryView.as_view(), name="selected-category"),
    path("lists/<int:list_id>/", SingleListView.as_view(), name="single-list"),
    # path("lists/<int:pk>/", CategoryDetailView.as_view(), name="category-detail"),
    path("lists/<int:list_id>/rename/", RenameListView.as_view(), name="list-rename"),
    path("lists/sort_order/", UpdateListsOrderingView.as_view(), name="update-lists-ordering"),

    # --- ✅ Operazioni su ToDo ---
    path("lists/<int:list_id>/todos/", TodoCreateView.as_view(), name="todo-create"),
    path("lists/<int:list_id>/sort_order/", UpdateOrderingView.as_view(), name="todo-reorder"),
    path("todos/<int:todo_id>/toggle/", TodoToggleView.as_view(), name="todo-toggle"),
    path("todos/<int:todo_id>/update/", TodoUpdateView.as_view(), name="todo-update"),
    path("todos/<int:todo_id>/", TodoDeleteView.as_view(), name="todo-delete"),
    path("todos/<int:todo_id>/move/", MoveTodoView.as_view(), name="todo-move"),


    # --- ✅ Notifiche ---
    path("notifications/", NotificationListView.as_view(), name="notifications-list"),
    path("notifications/<int:notif_id>/read/", NotificationMarkReadView.as_view(), name="notification-read"),
    path("notifications/mark_all_read/", NotificationMarkAllReadView.as_view(), name="notifications-mark-all-read"),
    path("notifications/<int:notif_id>/", NotificationDeleteView.as_view(), name="notification-delete"),
    path("notifications/preferences/", UpdateNotificationPreferencesView.as_view(), name="notification-preferences"),
    path("notifications/update/", CreateUpdateNotificationView.as_view(), name="notification-update"),
    path("notifications/save-fcm-token/", SaveFCMTokenView.as_view(), name="save-fcm-token"),

    # --- ✅ Sistema Amicizie ---
    path("users/", UsersListView.as_view(), name="users-list"),
    path("friends/", FriendsListView.as_view(), name="friends-list"),
    path("friend-requests/", FriendRequestsListView.as_view(), name="friend-requests-list"),
    path("friend-requests/send/<int:user_id>/", SendFriendRequestView.as_view(), name="send-friend-request"),
    path("friend-requests/<int:request_id>/accept/", AcceptFriendRequestView.as_view(), name="accept-friend-request"),
    path("friend-requests/<int:request_id>/reject/", RejectFriendRequestView.as_view(), name="reject-friend-request"),
    path("friends/<int:user_id>/remove/", RemoveFriendView.as_view(), name="remove-friend"),

    # --- ✅ Sistema Condivisione Liste ---
    path("lists/<int:list_id>/share/", ShareListView.as_view(), name="share-list"),
    path("lists/<int:list_id>/share/<int:user_id>/", UnshareListView.as_view(), name="unshare-list"),
    path("lists/<int:list_id>/shares/", ListSharesView.as_view(), name="list-shares"),

    # --- ✅ Sistema Condivisione Categorie ---
    path("categories/<int:category_id>/share/", ShareCategoryView.as_view(), name="share-category"),
    path("categories/<int:category_id>/share/<int:user_id>/", UnshareCategoryView.as_view(), name="unshare-category"),
    path("categories/<int:category_id>/shares/", CategorySharesView.as_view(), name="category-shares"),
]
