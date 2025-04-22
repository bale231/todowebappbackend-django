from django.urls import path
from .views import *

urlpatterns = [
    # --- ✅ Auth & Account ---
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("delete-account/", DeleteAccountView.as_view(), name="delete_account"),
    path("user/", CurrentUserView.as_view(), name="current_user"),
    path("update-profile/", UpdateProfileView.as_view(), name="update_profile"),
    path("update-theme/", UpdateThemeView.as_view(), name="update_theme"),
    path("send-verification-email/", SendEmailVerificationView.as_view(), name="send_verification_email"),
    path("verify-email/<uidb64>/<token>/", ConfirmEmailView.as_view(), name="verify_email"),
    path("reset-password/", SendResetPasswordEmailView.as_view(), name="send_reset_password"),
    path("reset-password/<uidb64>/<token>/", ResetPasswordConfirmView.as_view(), name="reset_password_confirm"),

    # --- ✅ Liste ToDo (Categorie) ---
    path("lists/", CategoryListView.as_view(), name="category-list"),  # tutte le liste
    path("lists/<int:list_id>/", SingleListView.as_view(), name="single-list"),  # dettaglio singola lista + todos
    path("lists/<int:pk>/", CategoryDetailView.as_view(), name="category-detail"),  # DEPRECATA se non la usi
    path("lists/<int:list_id>/rename/", RenameListView.as_view(), name="list-rename"),
    path("lists/<int:list_id>/sort_order/", UpdateOrderingView.as_view(), name="update-ordering"),

    # --- ✅ Operazioni su ToDo ---
    path("lists/<int:list_id>/todos/", TodoCreateView.as_view(), name="todo-create"),
    path("lists/<int:list_id>/reorder/", ReorderTodoView.as_view(), name="todo-reorder"),
    path("todos/<int:todo_id>/toggle/", TodoToggleView.as_view(), name="todo-toggle"),
    path("todos/<int:todo_id>/update/", TodoUpdateView.as_view(), name="todo-update"),
    path("todos/<int:todo_id>/", TodoDeleteView.as_view(), name="todo-delete"),
]
