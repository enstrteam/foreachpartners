from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from users.models import RefreshToken
from django.utils.timezone import now, timedelta

User = get_user_model()

class UserAPITests(APITestCase):
    def setUp(self):
        """Set up test data, including a registered user."""
        self.registered_user_email = 'user1@example.com'
        self.registered_user_password = 'password'

        # Create a registered user
        self.user = User.objects.create_user(
            email=self.registered_user_email,
            username='user1',
            password=self.registered_user_password
        )
        self.client.force_authenticate(user=self.user)  # Automatically authenticate for further tests

    def test_registration(self):
        """Test user registration with valid and invalid data."""
        url = '/api/register/'
        
        # Test successful registration
        data = {'email': 'newuser@example.com', 'password': 'newpassword'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], 'newuser@example.com')

        # Test registration with existing email
        data['email'] = self.registered_user_email
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # def test_login(self):
    #     """Test login with valid and invalid credentials."""
    #     url = '/api/login/'
    #     valid_data = {
    #         'email': self.registered_user_email,
    #         'password': self.registered_user_password
    #     }
    #     invalid_data = {
    #         'email': 'nonexistent@example.com',
    #         'password': 'randompassword'
    #     }

    #     # Test successful login
    #     response = self.client.post(url, valid_data)
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertIn('access_token', response.data)
    #     self.assertIn('refresh_token', response.data)

    #     # Test login with invalid credentials
    #     response = self.client.post(url, invalid_data)
    #     self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # def test_refresh_token(self):
    #     """Test refresh token generation."""
    #     url = '/api/refresh/'
        
    #     # Create a refresh token for the user
    #     refresh_token = RefreshToken.objects.create(
    #         user=self.user,
    #         expires_at=now() + timedelta(days=30)
    #     )

    #     # Test successful refresh
    #     response = self.client.post(url, {'refresh_token': str(refresh_token.token)})
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertIn('access_token', response.data)
    #     self.assertIn('refresh_token', response.data)

    #     # Test refresh with an invalid token
    #     response = self.client.post(url, {'refresh_token': 'invalidtoken'})
    #     self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # def test_logout(self):
    #     """Test logout by invalidating the refresh token."""
    #     url = '/api/logout/'

    #     # Create a refresh token for the user
    #     refresh_token = RefreshToken.objects.create(
    #         user=self.user,
    #         expires_at=now() + timedelta(days=30)
    #     )

    #     # Test logout with a valid token
    #     response = self.client.post(url, {'refresh_token': str(refresh_token.token)})
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)

    #     # Ensure the refresh token is invalidated
    #     self.assertFalse(RefreshToken.objects.filter(token=refresh_token.token).exists())

    #     # Test logout with invalid token
    #     response = self.client.post(url, {'refresh_token': 'invalidtoken'})
    #     self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # def test_me(self):
    #     """Test the /me endpoint to fetch and update user data."""
    #     url = '/api/me/'  # Me endpoint

    #     # Test fetching user details
    #     response = self.client.get(url)
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertEqual(response.data['email'], self.registered_user_email)

    #     # Test updating user details
    #     update_data = {'username': 'updateduser'}
    #     response = self.client.put(url, update_data)
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertEqual(response.data['username'], 'updateduser')
