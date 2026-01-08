import requests
import json
from typing import List, Dict, Optional
class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        
    def is_available(self) -> bool:
        """Check if Ollama is running and accessible"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=2)
            return response.status_code == 200
        except (requests.RequestException, ConnectionError, TimeoutError):
            return False
    
    def list_models(self) -> List[Dict]:
        """
        Get list of available models
        
        Returns:
            List of model information
        """
        try:
            response = requests.get(f"{self.api_url}/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('models', [])
        except Exception as e:
            print(f"Error listing models: {e}")
        return []
    
    def generate(self, model: str, prompt: str, system_prompt: Optional[str] = None,
                stream: bool = False, temperature: float = 0.1) -> str:
        """
        Generate response from Ollama model
        
        Args:
            model: Model name (e.g., 'llama2', 'mistral')
            prompt: User prompt
            system_prompt: System prompt for context
            stream: Whether to stream the response
            temperature: Lower = more focused/deterministic (0.0-1.0)
            
        Returns:
            Generated text response
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": temperature,  # Low temperature for security accuracy
                "top_p": 0.9,
                "top_k": 40,
            }
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = requests.post(
                f"{self.api_url}/generate",
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                if stream:
                    # Handle streaming response
                    full_response = ""
                    for line in response.iter_lines():
                        if line:
                            data = json.loads(line)
                            if 'response' in data:
                                full_response += data['response']
                    return full_response
                else:
                    data = response.json()
                    return data.get('response', '')
            else:
                return f"Error: {response.status_code} - {response.text}"
                
        except requests.exceptions.Timeout:
            return "Error: Request timed out. The model might be too large or the query too complex."
        except Exception as e:
            return f"Error generating response: {str(e)}"
    
    def chat(self, model: str, messages: List[Dict], temperature: float = 0.1) -> str:
        """
        Chat with model using conversation format
        
        Args:
            model: Model name
            messages: List of message dicts with 'role' and 'content'
            temperature: Response randomness (0.0-1.0)
            
        Returns:
            Generated response
        """
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            }
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/chat",
                json=payload,
                timeout=99999
            )
            
            if response.status_code == 200:
                # Ollama may return NDJSON (multiple JSON objects separated by newlines)
                chunks = []
                for line in response.text.splitlines():
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                        message = obj.get('message', {})
                        content = message.get('content', '') if isinstance(message, dict) else ''
                        if content:
                            chunks.append(content)
                    except Exception:
                        continue

                if chunks:
                    return ''.join(chunks)

                # Fallback to single JSON object parsing
                try:
                    data = response.json()
                    return data["message"]["content"]
                except Exception as parse_err:
                    return f"Error parsing response: {parse_err}"
            else:
                return f"Error: {response.status_code}"
                
        except Exception as e:
            return f"Error: {str(e)}"
