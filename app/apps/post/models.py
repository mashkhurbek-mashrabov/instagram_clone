from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import FileExtensionValidator, MaxLengthValidator

from common.models import BaseModel

User = get_user_model()


class Post(BaseModel):
    author = models.ForeignKey(User, related_name='posts', on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    image = models.ImageField(upload_to='post/images/', validators=[
        FileExtensionValidator(['jpg', 'jpeg', 'png']),
    ])
    caption = models.TextField(validators=[MaxLengthValidator(2000)])

    class Meta:
        db_table = 'posts'
        verbose_name = 'post'
        verbose_name_plural = 'posts'


class PostComment(BaseModel):
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)
    comment = models.TextField(validators=[MaxLengthValidator(1000)])
    parent = models.ForeignKey('self', on_delete=models.CASCADE, related_name='child', null=True, blank=True)


class PostLike(BaseModel):
    author = models.ForeignKey(User, related_name='post_likes', on_delete=models.CASCADE)
    post = models.ForeignKey(Post, related_name='post_likes', on_delete=models.CASCADE)

    class Meta:
        unique_together = ('author', 'post')


class CommentLike(BaseModel):
    author = models.ForeignKey(User, related_name='comment_likes', on_delete=models.CASCADE)
    comment = models.ForeignKey(PostComment, related_name='comment_likes', on_delete=models.CASCADE)

    class Meta:
        unique_together = ('author', 'comment')