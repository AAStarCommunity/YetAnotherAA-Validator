import "reflect-metadata";
import { createRequire } from "module";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module.js";
import { ValidationPipe } from "@nestjs/common";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { ConfigService } from "@nestjs/config";
import { GossipService } from "./modules/gossip/gossip.service.js";

const require = createRequire(import.meta.url);
const { version: APP_VERSION } = require("../package.json") as { version: string };

async function bootstrap() {
  // rawBody: true exposes the unparsed request body (req.rawBody) so the optional
  // x402 stateless-HMAC auth guard can verify the HMAC over the exact bytes sent.
  const app = await NestFactory.create(AppModule, { rawBody: true });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    })
  );

  app.enableCors();

  // Swagger configuration
  const config = new DocumentBuilder()
    .setTitle("BLS Signer Service API")
    .setDescription("API documentation for ERC4337 BLS signature aggregation service")
    .setVersion(APP_VERSION)
    .addTag("signature", "Signature operations")
    .addTag("node", "Node management")
    .addTag("admin", "Admin panel for node management")
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup("api", app, document);

  const configService = app.get(ConfigService);
  const port = configService.get<number>("port")!;
  const host = configService.get<string>("host")!;
  const publicUrl = configService.get<string>("publicUrl")!;

  // Get the HTTP server instance and pass it to GossipService
  const httpServer = app.getHttpServer();
  const gossipService = app.get(GossipService);
  gossipService.setHttpServer(httpServer);

  await app.listen(port, host);

  console.log(`🚀 BLS Signer Service is running on ${host}:${port}`);
  console.log(`📖 Swagger API documentation: ${publicUrl}/api`);
  console.log(`🔐 Admin Panel: ${publicUrl}/admin`);
  console.log(`🌐 WebSocket Gossip endpoint: ws://${host}:${port}/ws`);
  console.log(`📋 Available endpoints:`);
  console.log(`   GET /node/info - Get current node information`);
  console.log(`   POST /node/register - Register node on-chain`);
  console.log(`   POST /signature/sign - Sign message with this node`);
  console.log(`   POST /signature/aggregate - Sign and return as aggregate format`);
  console.log(`   GET /admin - Node management admin panel`);
  console.log(`   WS /ws - WebSocket gossip protocol endpoint`);
}

bootstrap();
