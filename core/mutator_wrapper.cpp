#include <stdint.h>
#include <string>
#include <cassert>

#include "MutationStage.hpp"

/*
 * AFL preserves the seed length other than havoc
 * arg mutation/function mutations are considered length-preserving
 * Appending/removing are length-modifying: let's do it only for havoc now.
 *
 * How to pick the argument when function mutation..?
 * -> Do randomly if havoc
 *
 */

HavocStage* havocStage;
extern "C" {

void mutate_havoc_init(uint8_t* testcase, uint32_t len, uint32_t stage_max) {
    assert(havocStage == nullptr);
    havocStage = new HavocStage(testcase, len);
    havocStage->setStageMax(stage_max);
}

/* Takes out_buf (seed) from AFL engine as an input and mutate in-place
 * Returns new len
 * */
uint32_t mutate_havoc(uint8_t* testcase, uint32_t len, int option) {

    if (option == 0)
        return havocStage->mutate(testcase, len);
    else
        return havocStage->generate(testcase, len);

}

void mutate_havoc_fini() {
    delete havocStage;
    havocStage = nullptr;
}


}


