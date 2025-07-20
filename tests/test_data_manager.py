import os
import unittest
from unittest.mock import patch, mock_open
from src.cti_agent.data_manager import download_file, download_and_unzip, update_local_data

class TestDataManager(unittest.TestCase):

    @patch("requests.get")
    def test_download_file(self, mock_get):
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.content = b"test content"
        mock_get.return_value = mock_response

        with patch("builtins.open", mock_open()) as mock_file:
            download_file("http://test.com/file.txt", "/fake/path/file.txt")
            mock_file.assert_called_with("/fake/path/file.txt", "wb")
            mock_file().write.assert_called_with(b"test content")

    @patch("requests.get")
    @patch("zipfile.ZipFile")
    def test_download_and_unzip(self, mock_zipfile, mock_get):
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.content = b"zip content"
        mock_get.return_value = mock_response

        mock_zip_instance = unittest.mock.Mock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip_instance

        download_and_unzip("http://test.com/file.zip", "/fake/path")
        mock_zip_instance.extractall.assert_called_with("/fake/path")

    @patch("src.cti_agent.data_manager.download_file")
    @patch("src.cti_agent.data_manager.download_and_unzip")
    @patch("os.makedirs")
    def test_update_local_data(self, mock_makedirs, mock_download_and_unzip, mock_download_file):
        update_local_data()
        mock_makedirs.assert_called_once()
        self.assertEqual(mock_download_file.call_count, 2)
        mock_download_and_unzip.assert_called_once()

if __name__ == "__main__":
    unittest.main()