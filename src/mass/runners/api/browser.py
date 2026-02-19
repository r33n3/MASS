"""Browser-based chat agent runner.

Uses Playwright to interact with AI chat agents embedded in web pages.
Sends messages via CSS selectors and reads responses, enabling sandbox
scenario testing and adversarial interrogation of browser-hosted agents.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from mass.runners.base import (
    BaseRunner,
    RunnerResult,
    RunnerStatus,
    register_runner,
)

logger = logging.getLogger(__name__)


def _ensure_playwright():
    """Import playwright, raising a clear error if not installed."""
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        raise ImportError(
            "playwright is required for browser agent testing. "
            "Install with: pip install playwright && playwright install chromium"
        )


@register_runner
class BrowserRunner(BaseRunner):
    """Interact with browser-embedded chat agents via Playwright.

    Launches a browser, navigates to a page with a chat widget, and
    communicates with the agent by typing into the input field, clicking
    send, and reading the response container.
    """

    name = "browser"
    description = "Browser-based chat agent runner via Playwright"
    provider = "browser"
    supports_async = True

    default_model = "browser-agent"

    def __init__(
        self,
        url: str = "",
        input_selector: str = "",
        output_selector: str = "",
        send_selector: str = "",
        *,
        wait_selector: str | None = None,
        headless: bool = True,
        response_stabilize_ms: int = 1500,
        timeout_ms: int = 30000,
        viewport_width: int = 1280,
        viewport_height: int = 720,
        page_setup_steps: list[dict[str, Any]] | None = None,
        auth: dict[str, Any] | None = None,
        model: str | None = None,
        **kwargs: Any,
    ):
        """Initialize browser runner.

        Args:
            url: Page URL containing the chat widget.
            input_selector: CSS selector for chat input field.
            output_selector: CSS selector for latest response element.
            send_selector: CSS selector for send/submit button.
            wait_selector: CSS selector for loading indicator (disappears when done).
            headless: Run browser headless.
            response_stabilize_ms: Wait for streaming to finish.
            timeout_ms: Max wait for response.
            viewport_width: Browser viewport width.
            viewport_height: Browser viewport height.
            page_setup_steps: Pre-chat automation steps.
            auth: Authentication configuration.
            model: Model identifier (cosmetic, for result metadata).
        """
        super().__init__(model=model or "browser-agent", **kwargs)

        self.url = url
        self.input_selector = input_selector
        self.output_selector = output_selector
        self.send_selector = send_selector
        self.wait_selector = wait_selector
        self.headless = headless
        self.response_stabilize_ms = response_stabilize_ms
        self.timeout_ms = timeout_ms
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.page_setup_steps = page_setup_steps or []
        self.auth_config = auth

        # Managed browser state (async)
        self._playwright = None
        self._browser = None
        self._page = None
        self._last_response_text: str = ""
        self._message_count: int = 0

    # ── Lifecycle ────────────────────────────────────────────────

    async def _ensure_page(self):
        """Launch browser and navigate to the chat page if not already open."""
        if self._page is not None:
            return

        _ensure_playwright()
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
        )
        context = await self._browser.new_context(
            viewport={"width": self.viewport_width, "height": self.viewport_height},
        )
        self._page = await context.new_page()

        # Handle auth cookies if configured
        if self.auth_config and self.auth_config.get("type") == "cookie":
            cookies = self.auth_config.get("credentials", {}).get("cookies", [])
            if cookies:
                await context.add_cookies(cookies)

        # Navigate to the target page
        logger.info("Navigating to %s", self.url)
        await self._page.goto(self.url, wait_until="domcontentloaded")

        # Execute setup steps (login, cookie consent, etc.)
        await self._run_setup_steps()

        # Wait for the chat input to appear
        await self._page.wait_for_selector(
            self.input_selector,
            state="visible",
            timeout=self.timeout_ms,
        )
        logger.info("Browser page ready, chat input visible")

    async def _run_setup_steps(self):
        """Execute pre-chat automation steps."""
        for step in self.page_setup_steps:
            action = step.get("action", "")
            selector = step.get("selector")
            value = step.get("value", "")
            wait_ms = step.get("wait_ms", 0)

            if action == "click" and selector:
                await self._page.click(selector, timeout=10000)
            elif action == "type" and selector:
                await self._page.fill(selector, value or "")
            elif action == "navigate" and value:
                await self._page.goto(value, wait_until="domcontentloaded")
            elif action == "wait":
                await asyncio.sleep(wait_ms / 1000 if wait_ms else 1)
            elif action == "select" and selector:
                await self._page.select_option(selector, value or "")

            if wait_ms and action != "wait":
                await asyncio.sleep(wait_ms / 1000)

    async def close(self):
        """Close the browser and clean up."""
        if self._page:
            try:
                await self._page.close()
            except Exception:
                pass
            self._page = None
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

    # ── Core interaction ─────────────────────────────────────────

    async def _count_messages(self) -> int:
        """Count current assistant messages in the chat."""
        elements = await self._page.query_selector_all(self.output_selector)
        return len(elements)

    async def _get_latest_response(self) -> str:
        """Get the text of the latest response element."""
        elements = await self._page.query_selector_all(self.output_selector)
        if not elements:
            return ""
        last = elements[-1]
        return (await last.inner_text()).strip()

    async def _send_and_wait(self, prompt: str) -> str:
        """Type a message, click send, and wait for the response.

        Returns the response text.
        """
        # Snapshot current state
        pre_count = await self._count_messages()

        # Type the message
        input_el = await self._page.wait_for_selector(
            self.input_selector, state="visible", timeout=5000,
        )
        await input_el.click()
        await input_el.fill("")  # clear
        await input_el.fill(prompt)

        # Click send
        send_btn = await self._page.wait_for_selector(
            self.send_selector, state="visible", timeout=5000,
        )
        await send_btn.click()

        # Wait for a new response to appear
        deadline = time.time() + (self.timeout_ms / 1000)
        response_text = ""

        while time.time() < deadline:
            # If there's a wait_selector (loading indicator), wait for it to disappear
            if self.wait_selector:
                try:
                    await self._page.wait_for_selector(
                        self.wait_selector,
                        state="hidden",
                        timeout=min(2000, int((deadline - time.time()) * 1000)),
                    )
                except Exception:
                    pass  # Indicator might not appear or already gone

            current_count = await self._count_messages()
            if current_count > pre_count:
                # New message appeared — read it
                response_text = await self._get_latest_response()

                # Wait for streaming to stabilize
                await asyncio.sleep(self.response_stabilize_ms / 1000)
                stabilized = await self._get_latest_response()

                if stabilized == response_text and response_text:
                    # Content hasn't changed — response is complete
                    break
                response_text = stabilized
            else:
                await asyncio.sleep(0.3)

        if not response_text and time.time() >= deadline:
            logger.warning("Timed out waiting for browser agent response")

        self._last_response_text = response_text
        self._message_count += 1
        return response_text

    async def _take_screenshot(self) -> bytes | None:
        """Take a screenshot of the current page state."""
        if self._page:
            try:
                return await self._page.screenshot()
            except Exception:
                return None
        return None

    # ── BaseRunner interface ─────────────────────────────────────

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt synchronously (wraps async implementation)."""
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        if loop and loop.is_running():
            # Already in an async context — create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    self.run_async(prompt, system_prompt, **kwargs),
                )
                return future.result(timeout=self.timeout_ms / 1000 + 10)
        else:
            return asyncio.run(self.run_async(prompt, system_prompt, **kwargs))

    async def run_async(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt against the browser chat agent.

        Args:
            prompt: Message to send to the chat agent.
            system_prompt: Ignored (browser agents have their own system prompt).
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with the agent's response.
        """
        start_time = time.time()

        try:
            await self._ensure_page()
            response_text = await self._send_and_wait(prompt)
            latency_ms = (time.time() - start_time) * 1000

            if not response_text:
                return self._create_result(
                    response="",
                    status=RunnerStatus.TIMEOUT,
                    latency_ms=latency_ms,
                    error="No response received from browser agent within timeout",
                    metadata={
                        "url": self.url,
                        "message_number": self._message_count,
                    },
                )

            return self._create_result(
                response=response_text,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                metadata={
                    "url": self.url,
                    "message_number": self._message_count,
                },
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logger.error("Browser runner error: %s", e, exc_info=True)
            return self._create_result(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=latency_ms,
                error=str(e),
                metadata={"url": self.url},
            )

    # ── Utility ──────────────────────────────────────────────────

    async def test_connection(self) -> dict[str, Any]:
        """Test that selectors work and the chat widget is accessible.

        Returns a dict with status, screenshot bytes, and any errors.
        """
        _ensure_playwright()
        result: dict[str, Any] = {
            "status": "error",
            "url": self.url,
            "selectors_found": {},
            "screenshot": None,
            "error": None,
        }

        try:
            await self._ensure_page()

            # Check each selector
            for label, sel in [
                ("input", self.input_selector),
                ("output", self.output_selector),
                ("send", self.send_selector),
            ]:
                el = await self._page.query_selector(sel)
                result["selectors_found"][label] = el is not None

            if self.wait_selector:
                el = await self._page.query_selector(self.wait_selector)
                result["selectors_found"]["wait"] = el is not None

            result["screenshot"] = await self._take_screenshot()
            result["status"] = "ok" if all(
                v for k, v in result["selectors_found"].items()
                if k != "wait"  # wait_selector is optional
            ) else "selectors_missing"

        except Exception as e:
            result["error"] = str(e)
            logger.error("Browser connection test failed: %s", e, exc_info=True)

        return result
