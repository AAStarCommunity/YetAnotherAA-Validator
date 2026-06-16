import { Module } from "@nestjs/common";
import { ConfirmationService } from "./confirmation.service.js";
import { NotificationModule } from "../notification/notification.module.js";

@Module({
  imports: [NotificationModule],
  providers: [ConfirmationService],
  exports: [ConfirmationService],
})
export class ConfirmationModule {}
