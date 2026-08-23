import { Body, Controller, Post, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { ThrottleGuard } from "../../common/throttle.guard.js";
import type { RepCreditCoSignResponse, RepCreditProposal } from "./repcredit-consensus.js";
import { RepCreditService } from "./repcredit.service.js";

@ApiTags("repcredit-experiment")
@Controller("repcredit")
@UseGuards(ThrottleGuard)
export class RepCreditController {
  constructor(private readonly service: RepCreditService) {}

  @Post("sign")
  @ApiOperation({ summary: "Sign a locally recomputed structured RepCredit proposal (opt-in)" })
  sign(@Body() proposal: RepCreditProposal) {
    return this.service.sign(proposal);
  }

  @Post("aggregate")
  @ApiOperation({ summary: "Validate and aggregate RepCredit node responses (opt-in)" })
  aggregate(
    @Body()
    body: {
      proposal: RepCreditProposal;
      responses: RepCreditCoSignResponse[];
      threshold: number;
    }
  ) {
    return this.service.aggregate(body.proposal, body.responses, body.threshold);
  }
}
