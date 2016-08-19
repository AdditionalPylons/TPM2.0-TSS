#ifndef TCTI_TBS_H
#define TCTI_TBS_H

#include <sapi/tpm20.h>
#include <tcti/common.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct {
		TCTI_LOG_CALLBACK logCallback;
		TCTI_LOG_BUFFER_CALLBACK logBufferCallback;
		void *logData;
	} TCTI_TBS_CONF;

	TSS2_RC InitTbsTcti(
		TSS2_TCTI_CONTEXT *tctiContext, // OUT
		size_t *contextSize, // IN/OUT
		const TCTI_TBS_CONF *conf // IN
	);
#ifdef __cplusplus
}
#endif
#endif