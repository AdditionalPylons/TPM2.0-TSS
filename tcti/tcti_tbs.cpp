//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, 
// this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, 
// this list of conditions and the following disclaimer in the documentation 
// and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#ifdef  _WIN32

#include <stdio.h>
#include <tcti/tcti_tbs.h>
#include <sapi/tss2_common.h>
#include <Tbs.h>
#include "sysapi_util.h"
#include "logging.h"
#include "commonchecks.h"
#include "debug.h"

#ifndef TCTI_CONTEXT_INTEL
#define TCTI_CONTEXT_INTEL ( (TSS2_TCTI_CONTEXT_INTEL *)tctiContext )
#endif

#define FORMAT_TBS_ERR(dest, code, description) snprintf(dest, sizeof(dest), "Error %s (0x%08x): %s", #code, code, description)

#ifdef __cplusplus
extern "C" {
#endif

	TSS2_RC decodeTbsError(const TSS2_TCTI_CONTEXT *tctiContext, const TBS_RESULT err)
	{
		if (tctiContext == NULL)
		{
			return TSS2_TCTI_RC_BAD_REFERENCE;
		}

		bool prefix = TCTI_CONTEXT_INTEL->status.rmDebugPrefix;

		char errMsg[64];
		TSS2_RC rval;
		switch (err)
		{
		case TBS_E_BAD_PARAMETER:
			FORMAT_TBS_ERR(errMsg, TBS_E_BAD_PARAMETER, "One or more parameter values are not valid.");
			rval = TSS2_TCTI_RC_BAD_VALUE;
		case TBS_E_INTERNAL_ERROR:
			FORMAT_TBS_ERR(errMsg, TBS_E_INTERNAL_ERROR, "An internal software error occurred.");
			rval = TSS2_TCTI_RC_GENERAL_FAILURE;
		case TBS_E_INVALID_CONTEXT_PARAM:
			FORMAT_TBS_ERR(errMsg, TBS_E_INVALID_CONTEXT_PARAM, "A context parameter that is not valid was passed when attempting to create a TBS context.");
			rval = TSS2_TCTI_RC_BAD_CONTEXT;
		case TBS_E_INVALID_OUTPUT_POINTER:
			FORMAT_TBS_ERR(errMsg, TBS_E_INVALID_OUTPUT_POINTER, "A specified output pointer is not valid.");
			rval = TSS2_TCTI_RC_BAD_REFERENCE;
		case TBS_E_SERVICE_DISABLED:
			FORMAT_TBS_ERR(errMsg, TBS_E_SERVICE_DISABLED, "The TBS service has been disabled.");
			rval = TSS2_TCTI_RC_NO_CONNECTION;
		case TBS_E_SERVICE_NOT_RUNNING:
			FORMAT_TBS_ERR(errMsg, TBS_E_SERVICE_NOT_RUNNING, "The TBS service is not running and could not be started.");
			rval = TSS2_TCTI_RC_NO_CONNECTION;
		case TBS_E_SERVICE_START_PENDING:
			FORMAT_TBS_ERR(errMsg, TBS_E_SERVICE_START_PENDING, "The TBS service has been started but is not yet running.");
			rval = TSS2_TCTI_RC_TRY_AGAIN;
		case TBS_E_TOO_MANY_TBS_CONTEXTS:
			FORMAT_TBS_ERR(errMsg, TBS_E_TOO_MANY_TBS_CONTEXTS, "A new context could not be created because there are too many open contexts.");
			rval = TSS2_TCTI_RC_TRY_AGAIN;
		case TBS_E_TPM_NOT_FOUND:
			FORMAT_TBS_ERR(errMsg, TBS_E_TPM_NOT_FOUND, "A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer.");
			rval = TSS2_TCTI_RC_NOT_SUPPORTED;
		case TBS_E_BUFFER_TOO_LARGE:
			FORMAT_TBS_ERR(errMsg, TBS_E_BUFFER_TOO_LARGE, "The input or output buffer is too large.");
			rval = TSS2_TCTI_RC_BAD_VALUE;
		case TBS_E_INSUFFICIENT_BUFFER:
			FORMAT_TBS_ERR(errMsg, TBS_E_INSUFFICIENT_BUFFER, "The specified output buffer is too small.");
			rval = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		case TBS_E_IOERROR:
			FORMAT_TBS_ERR(errMsg, TBS_E_IOERROR, "An error occurred while communicating with the TPM.");
			rval = TSS2_TCTI_RC_IO_ERROR;
		default:
			snprintf(errMsg, sizeof(errMsg), "Unknown TBS Error");
			rval = TSS2_TCTI_RC_GENERAL_FAILURE;
		}
		TCTI_LOG(tctiContext, (prefix ? RM_PREFIX : NO_PREFIX), errMsg);
		return rval;
	}

	void TbsFinalize(
		TSS2_TCTI_CONTEXT		*tctiContext	// IN		
	)
	{
		if (tctiContext != NULL)
		{
			TBS_HCONTEXT tbsContext = TCTI_CONTEXT_INTEL->tbsContext;
			if (tbsContext != NULL)
			{
				TBS_RESULT res = Tbsip_Context_Close(tbsContext);
				if (res != TBS_SUCCESS)
				{
					decodeTbsError(tctiContext, res);
				}
			}
			TCTI_LOG(tctiContext, NO_PREFIX, "Warning: tried to finalize a NULL tctiContext.");
		}
	}

	TSS2_RC TbsSendTpmCommand(
		TSS2_TCTI_CONTEXT		*tctiContext,	// IN
		size_t					commandSize,	// IN
		uint8_t					*commandBuffer  // IN
	)
	{
		TSS2_RC rval = TSS2_RC_SUCCESS;		

		rval = CommonSendChecks(tctiContext, commandBuffer);
		if (rval != TSS2_RC_SUCCESS)
		{
			// common security checks failed, return failure immediately
			return rval;
		}

		TBS_HCONTEXT tbsContext = TCTI_CONTEXT_INTEL->tbsContext;
		BYTE resultBuffer[sizeof(TCTI_CONTEXT_INTEL->responseBuffer)];
		size_t resultSize = sizeof(resultBuffer);

		TBS_RESULT res = Tbsip_Submit_Command(
			tbsContext,
			TBS_COMMAND_LOCALITY_ZERO, // Only ZERO is supported right now
			TBS_COMMAND_PRIORITY_NORMAL,
			commandBuffer,
			commandSize,
			resultBuffer,
			&resultSize);

		/*
			If Submit_Command fails because of insufficient buffer space, it will yield the required size in *resultSize.
			This means that we could malloc the required bytes if necessary. However, malloc should be avoided where not necessary for secure code.
		*/
		if (res != TBS_SUCCESS)
		{
			TCTI_CONTEXT_INTEL->responseSize = 0;
			return decodeTbsError(tctiContext, res);
		}
		else
		{
			TCTI_CONTEXT_INTEL->previousStage = TCTI_STAGE_SEND_COMMAND;

			// memcpy_s will make sure resultSize fits into sizeof(responseBuffer)
			if (memcpy_s(TCTI_CONTEXT_INTEL->responseBuffer, sizeof(TCTI_CONTEXT_INTEL->responseBuffer), resultBuffer, resultSize) == 0)
			{
				// SUCCESS
				TCTI_CONTEXT_INTEL->responseSize = resultSize;
			}
			else
			{
				// success
				TCTI_CONTEXT_INTEL->responseSize = 0;
				rval = TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
				TCTI_LOG(tctiContext, (printf_type)TCTI_CONTEXT_INTEL->status.rmDebugPrefix, "CRITICAL ERROR: Received a TpmResponse greater than 4096 bytes.");
			}
		}

		return rval;
	}

	TSS2_RC TbsReceiveTpmResponse(
		TSS2_TCTI_CONTEXT	*tctiContext,		// IN
		size_t				*responseSize,		// OUT
		BYTE				*responseBuffer,	// IN
		int32_t				timeout				// IN
	)
	{
		/*
			This function should operate with the assumption that TbsSendCommand successfully handedl the receiving
		*/
		TSS2_RC rval = TSS2_RC_SUCCESS;		

		rval = CommonReceiveChecks(tctiContext, responseSize, responseBuffer);
		if (rval != TSS2_RC_SUCCESS)
		{
			return rval;
		}

		if (responseBuffer == NULL)
		{
			// return just the size;
			*responseSize = TCTI_CONTEXT_INTEL->responseSize;
			return rval;
		} 		

		if (memcpy_s(responseBuffer, *responseSize, TCTI_CONTEXT_INTEL->responseBuffer, TCTI_CONTEXT_INTEL->responseSize) == 0)
		{
			// success
			*responseSize = TCTI_CONTEXT_INTEL->responseSize;
			TCTI_CONTEXT_INTEL->status.commandSent = 0;
			TCTI_CONTEXT_INTEL->previousStage = TCTI_STAGE_RECEIVE_RESPONSE;

#ifdef DEBUG
			if (TCTI_CONTEXT_INTEL->status.debugMsgEnabled && TCTI_CONTEXT_INTEL->responseSize > 0)
			{
				printf_type rmPrefix = (printf_type)TCTI_CONTEXT_INTEL->status.rmDebugPrefix;
				TCTI_LOG(tctiContext, rmPrefix, "\n");
				TCTI_LOG(tctiContext, rmPrefix, "Resposne Received: ");
				DEBUG_PRINT_BUFFER(rmPrefix, responseBuffer, TCTI_CONTEXT_INTEL->responseSize);
			}
#endif
			return rval;
		}
		else
		{			
			*responseSize = TCTI_CONTEXT_INTEL->responseSize;
			return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
		}
				
	}

	TSS2_RC TbsSetLocality(
		TSS2_TCTI_CONTEXT	*tctiContext,	// IN
		uint8_t				locality		// IN
	)
	{
		// TBS only supports locality zero as of right now, so this isnt supported
		return TSS2_TCTI_RC_NOT_SUPPORTED;
	}

	TSS2_RC TbsTpmCancel(
		TSS2_TCTI_CONTEXT *tctiContext
	)
	{
		TSS2_RC rval = TSS2_RC_SUCCESS;

		if (tctiContext == NULL)
		{
			return TSS2_TCTI_RC_BAD_REFERENCE;
		}

		TBS_RESULT res = Tbsip_Cancel_Commands(TCTI_CONTEXT_INTEL->tbsContext);
		if (res != TBS_SUCCESS) 
		{
			rval = decodeTbsError(tctiContext, res);			
		}
		return rval;
	}

	TSS2_RC InitTbsTcti(
		TSS2_TCTI_CONTEXT *tctiContext, // OUT
		size_t *contextSize, // IN/OUT
		const TCTI_TBS_CONF *conf // IN
	)
	{

		TBS_HCONTEXT tbsContext;
		TSS2_RC rval = TSS2_RC_SUCCESS;

		if (tctiContext == NULL)
		{
			*contextSize = sizeof(TSS2_TCTI_CONTEXT_INTEL);
			return TSS2_RC_SUCCESS;
		}
		else
		{
			// Setup context functions
			TSS2_TCTI_MAGIC(tctiContext) = TCTI_MAGIC;
			TSS2_TCTI_VERSION(tctiContext) = TCTI_VERSION;
			TSS2_TCTI_TRANSMIT(tctiContext) = TbsSendTpmCommand;
			TSS2_TCTI_RECEIVE(tctiContext) = TbsReceiveTpmResponse;
			TSS2_TCTI_FINALIZE(tctiContext) = TbsFinalize;
			TSS2_TCTI_CANCEL(tctiContext) = TbsTpmCancel;
			TSS2_TCTI_GET_POLL_HANDLES(tctiContext) = 0;
			TSS2_TCTI_SET_LOCALITY(tctiContext) = TbsSetLocality;

			// TCTI_CONTEXT_INTEL macro casts loal variable tctiContext to INTEL version
			TCTI_CONTEXT_INTEL->status.locality = TBS_COMMAND_LOCALITY_ZERO; // Only Locality Zero is supported for TBS right now
			TCTI_CONTEXT_INTEL->status.commandSent = 0;
			TCTI_CONTEXT_INTEL->status.rmDebugPrefix = 0;
			TCTI_CONTEXT_INTEL->currentTctiContext = 0;
			TCTI_CONTEXT_INTEL->previousStage = TCTI_STAGE_INITIALIZE;

			// Setup logging functions
			TCTI_LOG_CALLBACK(tctiContext) = conf->logCallback;
			TCTI_LOG_BUFFER_CALLBACK(tctiContext) = conf->logBufferCallback;
			TCTI_LOG_DATA(tctiContext) = conf->logData;

			// clear response size which might be garbage data
			TCTI_CONTEXT_INTEL->responseSize = 0;

			// Create a Windows TBS TPM 2.0 only context
			TBS_CONTEXT_PARAMS2 params;
			params.includeTpm12 = FALSE;
			params.includeTpm20 = TRUE;
			params.version = TBS_CONTEXT_VERSION_TWO;
			TBS_RESULT res = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &tbsContext);

			if (res != TBS_SUCCESS)
			{
				return decodeTbsError(tctiContext, res);
			}
			else
			{
				TCTI_CONTEXT_INTEL->tbsContext = tbsContext;
			}
		}
		return rval;
	}

#ifdef __cplusplus
}
#endif
#endif