import ssl
import asyncio
from typing import Dict, Any
import aiohttp

COMMON_HTTP_PORTS = {80, 8080, 8000}
COMMON_HTTPS_PORTS = {443, 8443}


class BannerGrabber:
    async def grab(self, host: str, port: int, reader=None, writer=None):
        """
        Grab banner/service info from a port.
        Optionally reuses an already open (reader, writer).
        """
        info = {"host": host, "port": port, "raw": None, "service": None}

        if port in COMMON_HTTPS_PORTS:
            http = await self._grab_http(host, port, use_ssl=True)
            info.update({"raw": http.get("server") or http.get("title"),
                         "http": http,
                         "service": http.get("server")})
            tls = await self._grab_tls(host, port)
            if tls:
                info["tls"] = tls
            return info

        if port in COMMON_HTTP_PORTS:
            http = await self._grab_http(host, port, use_ssl=False)
            info.update({"raw": http.get("server") or http.get("title"),
                         "http": http,
                         "service": http.get("server")})
            return info

        # Fallback: raw socket banner
        try:
            if reader and writer:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                except asyncio.TimeoutError:
                    data = b""
                text = data.decode(errors="ignore").strip() if data else ""
                info.update({"raw": text, "service": text.split()[0] if text else None})

                # SMTP extra handshake
                if port == 25:
                    try:
                        writer.write(b"EHLO vulnscan\r\n")
                        await writer.drain()
                        data2 = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                        info["raw"] = (info.get("raw") or "") + " | " + data2.decode(errors="ignore").strip()
                    except Exception:
                        pass
                return info
        except Exception:
            pass

        # If no reader provided, open a new socket
        try:
            reader2, writer2 = await asyncio.open_connection(host, port)
            try:
                writer2.write(b"\r\n")
                await writer2.drain()
                data = await asyncio.wait_for(reader2.read(4096), timeout=1.0)
                text = data.decode(errors="ignore").strip() if data else ""
                info.update({"raw": text, "service": text.split()[0] if text else None})
            finally:
                try:
                    writer2.close()
                    await writer2.wait_closed()
                except Exception:
                    pass
        except Exception:
            pass

        return info

    async def _grab_http(self, host: str, port: int, use_ssl: bool = False) -> Dict[str, Any]:
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}/"
        out = {"server": None, "title": None, "url": url}
        timeout = aiohttp.ClientTimeout(total=5)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as resp:
                    out["server"] = resp.headers.get("Server")
                    body = await resp.text()
                    if "<title" in body.lower():
                        start = body.lower().find("<title")
                        gt = body.find(">", start)
                        end = body.find("</title>", gt)
                        if gt != -1 and end != -1:
                            out["title"] = body[gt+1:end].strip()
        except Exception:
            pass
        return out

    async def _grab_tls(self, host: str, port: int) -> Dict[str, Any]:
        try:
            ctx = ssl._create_unverified_context()  # allow self-signed
            reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert()
            writer.close()
            await writer.wait_closed()
            return {"cert": cert}
        except Exception:
            return {}
