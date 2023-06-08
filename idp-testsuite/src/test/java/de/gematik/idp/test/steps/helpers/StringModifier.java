/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.helpers;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public final class StringModifier {

  public static String flipBit(final int bitIdx, final String value) {
    final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    final int idx;
    final int shift;
    if (bitIdx < 0) {
      idx = bytes.length - 1 + bitIdx / 8;
      shift = -bitIdx % 8;
    } else {
      idx = bitIdx / 8;
      shift = 8 - (bitIdx % 8);
    }
    bytes[idx] ^= (byte) (0b00000001 << shift);
    final String flippedValue = new String(bytes);
    assertThat(flippedValue).isNotEqualTo(value);
    return flippedValue;
  }

  @Test
  void testFlipBitFromBegin() {
    final String orig =
        "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiY3R5IjoiTkpXVCIsIng1YyI6WyJNSUlEWGpDQ0F3V2dBd0lCQWdJSEFQZ0QyZHZucXpBS0JnZ3Foa2pPUFFRREFqQ0JsakVMTUFrR0ExVUVCaE1DUkVVeEh6QWRCZ05WQkFvTUZtZGxiV0YwYVdzZ1IyMWlTQ0JPVDFRdFZrRk1TVVF4UlRCREJnTlZCQXNNUEVWc1pXdDBjbTl1YVhOamFHVWdSMlZ6ZFc1a2FHVnBkSE5yWVhKMFpTMURRU0JrWlhJZ1ZHVnNaVzFoZEdscmFXNW1jbUZ6ZEhKMWEzUjFjakVmTUIwR0ExVUVBd3dXUjBWTkxrVkhTeTFEUVRFd0lGUkZVMVF0VDA1TVdUQWVGdzB4TnpFeE1qTXdNREF3TURCYUZ3MHlNakV4TWpJeU16VTVOVGxhTUlITk1UNHdQQVlEVlFRREREVkVZWEpwZFhNZ1RXbGphR0ZsYkNCQ2NtbGhiaUJWWW1KdklFZHlZV1lnZG05dUlFTER0bVJsWm1Wc1pGUkZVMVF0VDA1TVdURVNNQkFHQTFVRUJBd0pRc08yWkdWbVpXeGtNU0l3SUFZRFZRUXFEQmxFWVhKcGRYTWdUV2xqYUdGbGJDQkNjbWxoYmlCVlltSnZNUk13RVFZRFZRUUxEQXBZTVRFd05ERXhOamMxTVJJd0VBWURWUVFMREFreE1EazFNREE1TmpreEhUQWJCZ05WQkFvTUZGUmxjM1FnUjB0V0xWTldUazlVTFZaQlRFbEVNUXN3Q1FZRFZRUUdFd0pFUlRCYU1CUUdCeXFHU000OUFnRUdDU3NrQXdNQ0NBRUJCd05DQUFRNGVITDhDMDJjQ0UzbWdzWFp4ZFNRZnZBakFUVEFpK1FUOHo3NnFGWkY3Vnk4QTc1dTgweU41c3hLTWI2OU1KYU1tQ2dobFNQckdoSEtjaU9iME1KeW80SUJBakNCL3pBd0JnVXJKQWdEQXdRbk1DVXdJekFoTUI4d0hUQVFEQTVXWlhKemFXTm9aWEowWlM4dGNqQUpCZ2NxZ2hRQVRBUXhNQ0FHQTFVZElBUVpNQmN3Q2dZSUtvSVVBRXdFZ1NNd0NRWUhLb0lVQUV3RVJqQU9CZ05WSFE4QkFmOEVCQU1DQjRBd1N3WUlLd1lCQlFVSEFRRUVQekE5TURzR0NDc0dBUVVGQnpBQmhpOW9kSFJ3T2k4dmIyTnpjQzV3YTJrdWRHVnNaVzFoZEdsckxYUmxjM1E2T0RBNE1DOURUVTlEVTFBdlQwTlRVREFkQmdOVkhRNEVGZ1FVZWgvNjdDVE0wbWwyTElqUmdpT1libXFXUWQ4d0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3REFZRFZSMFRBUUgvQkFJd0FEQUtCZ2dxaGtqT1BRUURBZ05IQURCRUFpQW9UbU9hYlFyNWFDZjR5S01OaWhYVGNCbXpNdlN0SmlPOWpvZDJ0RlhwU1FJZ1BEamduTDVqa2VMOGtuRXhpeWUwNElSQWx6VlN6VE9pdTFESFh3QW5qTjQ9Il19";
    final String flipped = flipBit(12, orig);
    final int expectedByteIdx = 1;

    for (int i = 0, n = orig.length(); i < n; i++) {
      if (orig.charAt(i) != flipped.charAt(i)) {
        assertThat(i)
            .as("The second byte (byte[1] should have been changed.")
            .isEqualTo(expectedByteIdx);
      }
    }
  }

  @Test
  void testFlipBitFromEnd() {
    final String orig =
        "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwiY3R5IjoiTkpXVCIsIng1YyI6WyJNSUlEWGpDQ0F3V2dBd0lCQWdJSEFQZ0QyZHZucXpBS0JnZ3Foa2pPUFFRREFqQ0JsakVMTUFrR0ExVUVCaE1DUkVVeEh6QWRCZ05WQkFvTUZtZGxiV0YwYVdzZ1IyMWlTQ0JPVDFRdFZrRk1TVVF4UlRCREJnTlZCQXNNUEVWc1pXdDBjbTl1YVhOamFHVWdSMlZ6ZFc1a2FHVnBkSE5yWVhKMFpTMURRU0JrWlhJZ1ZHVnNaVzFoZEdscmFXNW1jbUZ6ZEhKMWEzUjFjakVmTUIwR0ExVUVBd3dXUjBWTkxrVkhTeTFEUVRFd0lGUkZVMVF0VDA1TVdUQWVGdzB4TnpFeE1qTXdNREF3TURCYUZ3MHlNakV4TWpJeU16VTVOVGxhTUlITk1UNHdQQVlEVlFRREREVkVZWEpwZFhNZ1RXbGphR0ZsYkNCQ2NtbGhiaUJWWW1KdklFZHlZV1lnZG05dUlFTER0bVJsWm1Wc1pGUkZVMVF0VDA1TVdURVNNQkFHQTFVRUJBd0pRc08yWkdWbVpXeGtNU0l3SUFZRFZRUXFEQmxFWVhKcGRYTWdUV2xqYUdGbGJDQkNjbWxoYmlCVlltSnZNUk13RVFZRFZRUUxEQXBZTVRFd05ERXhOamMxTVJJd0VBWURWUVFMREFreE1EazFNREE1TmpreEhUQWJCZ05WQkFvTUZGUmxjM1FnUjB0V0xWTldUazlVTFZaQlRFbEVNUXN3Q1FZRFZRUUdFd0pFUlRCYU1CUUdCeXFHU000OUFnRUdDU3NrQXdNQ0NBRUJCd05DQUFRNGVITDhDMDJjQ0UzbWdzWFp4ZFNRZnZBakFUVEFpK1FUOHo3NnFGWkY3Vnk4QTc1dTgweU41c3hLTWI2OU1KYU1tQ2dobFNQckdoSEtjaU9iME1KeW80SUJBakNCL3pBd0JnVXJKQWdEQXdRbk1DVXdJekFoTUI4d0hUQVFEQTVXWlhKemFXTm9aWEowWlM4dGNqQUpCZ2NxZ2hRQVRBUXhNQ0FHQTFVZElBUVpNQmN3Q2dZSUtvSVVBRXdFZ1NNd0NRWUhLb0lVQUV3RVJqQU9CZ05WSFE4QkFmOEVCQU1DQjRBd1N3WUlLd1lCQlFVSEFRRUVQekE5TURzR0NDc0dBUVVGQnpBQmhpOW9kSFJ3T2k4dmIyTnpjQzV3YTJrdWRHVnNaVzFoZEdsckxYUmxjM1E2T0RBNE1DOURUVTlEVTFBdlQwTlRVREFkQmdOVkhRNEVGZ1FVZWgvNjdDVE0wbWwyTElqUmdpT1libXFXUWQ4d0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3REFZRFZSMFRBUUgvQkFJd0FEQUtCZ2dxaGtqT1BRUURBZ05IQURCRUFpQW9UbU9hYlFyNWFDZjR5S01OaWhYVGNCbXpNdlN0SmlPOWpvZDJ0RlhwU1FJZ1BEamduTDVqa2VMOGtuRXhpeWUwNElSQWx6VlN6VE9pdTFESFh3QW5qTjQ9Il19";
    final String flipped = flipBit(-20, orig);
    final int expectedByteIdx = -3;

    for (int i = 0, n = orig.length(); i < n; i++) {
      if (orig.charAt(i) != flipped.charAt(i)) {
        assertThat(i)
            .as(
                "The third byte from the end should have been changed. byte amount: "
                    + orig.length())
            .isEqualTo(orig.length() + expectedByteIdx);
      }
    }
  }
}
