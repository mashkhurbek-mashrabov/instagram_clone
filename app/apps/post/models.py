from django.db import models
from common.models import BaseModel
from django.contrib.auth import get_user_model
from django.core.validators import FileExtensionValidator, MaxLengthValidator

User = get_user_model()

class Post(BaseModel):
    auth = models.ForeignKey(User, related_name='posts', on_delete=models.CASCADE)
    image = models.ImageField(upload_to='posts/', 
                              validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])])
    caption = models.TextField(validators=[MaxLengthValidator(2000)])