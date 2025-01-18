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

    def test_registration(self):
        """Test user registration with valid and invalid data."""
        url = '/api/register/'  # Registration endpoint

        data = {
            'email': 'testuser5@example.com',
            'password': 'newpassword',
        }

        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], 'testuser5@example.com')

        data_duplicate = {
            'email': self.registered_user_email,
            'password': 'anotherpassword',
        }

        response_duplicate = self.client.post(url, data_duplicate)
        self.assertEqual(response_duplicate.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response_duplicate.data)
        self.assertEqual(response_duplicate.data['email'][0], 'user with this email already exists.')

        data['email'] = self.registered_user_email
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


    def test_login(self):
        """Test login with valid and invalid credentials."""
        url = '/api/login/'  # Login endpoint
        valid_data = {
            'email': self.registered_user_email,
            'password': self.registered_user_password
        }
        invalid_data = {
            'email': 'nonexistent@example.com',
            'password': 'randompassword'
        }

        # Test successful login
        response = self.client.post(url, valid_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)

        # Test login with invalid credentials
        response = self.client.post(url, invalid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_me_endpoint(self):
        """Test the /me endpoint to fetch and update user data."""
        url = '/api/me/'  # Me endpoint

        # Authenticate the user
        self.client.force_authenticate(user=self.user)

        # Test fetching user details
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.registered_user_email)
        self.assertEqual(response.data['username'], 'user1')

        # Test updating user details
        update_data = {'username': 'updateduser'}
        response = self.client.put(url, update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'updateduser')

    def test_logout(self):
        """Test logout by invalidating the refresh token."""
        # Create a refresh token for the user
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            expires_at=now() + timedelta(days=30)
        )

        url = '/api/logout/'  # Logout endpoint
        data = {'refresh_token': str(refresh_token.token)}

        # Test logout with a valid token
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Ensure the refresh token is invalidated
        self.assertFalse(RefreshToken.objects.filter(token=refresh_token.token).exists())

    def test_refresh_token(self):
        """Test refresh token generation."""
        # Create a refresh token for the user
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            expires_at=now() + timedelta(days=30)
        )

        url = '/api/refresh/'  # Refresh endpoint
        data = {'refresh_token': str(refresh_token.token)}

        # Test successful refresh
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)

        # Test refresh with an invalid token
        response = self.client.post(url, {'refresh_token': 'invalidtoken'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_and_login(self):
        """Test registration and then login with the same credentials."""
        url_register = '/api/register/'  # Registration endpoint
        url_login = '/api/login/'  # Login endpoint

        # Registration data
        registration_data = {
            'email': 'testuser@example.com',
            'password': 'testpassword',
        }

        # Register the user
        response_register = self.client.post(url_register, registration_data)
        self.assertEqual(response_register.status_code, status.HTTP_201_CREATED)

        # Login data
        login_data = {
            'email': 'testuser@example.com',
            'password': 'testpassword',
        }

        # Login with the same credentials
        response_login = self.client.post(url_login, login_data)
        self.assertEqual(response_login.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response_login.data)
        self.assertIn('refresh_token', response_login.data)

    def test_registration_with_existing_email(self):
        """Test registration with an already existing email."""
        url_register = '/api/register/'  # Registration endpoint

        # First registration
        registration_data = {
            'email': 'existinguser@example.com',
            'password': 'password123',
        }
        response_first = self.client.post(url_register, registration_data)
        self.assertEqual(response_first.status_code, status.HTTP_201_CREATED)

        # Second registration with the same email
        response_second = self.client.post(url_register, registration_data)
        self.assertEqual(response_second.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response_second.data)
