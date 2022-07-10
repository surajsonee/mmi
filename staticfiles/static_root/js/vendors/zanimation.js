/*-----------------------------------------------
|                 Zanimation
-----------------------------------------------*/

import utils from "./utils";
/*
global CustomEase, gsap
*/
CustomEase.create("CubicBezier", ".77,0,.18,1");

/*-----------------------------------------------
|   Global Functions
-----------------------------------------------*/
const filterBlur = () => {
  let blur = "blur(5px)";
  const isIpadIphoneMacFirefox =
    (window.is.ios() || window.is.mac()) && window.is.firefox();
  if (isIpadIphoneMacFirefox) {
    blur = "blur(0px)";
  }
  return blur;
};


const zanimationEffects = {
  default: {
    from: {
      opacity: 0,
      y: 70,
    },
    to: {
      opacity: 1,
      y: 0,
    },
    ease: 'CubicBezier',
    duration: 0.8,
    delay: 0,
  },

  'slide-down': {
    from: {
      opacity: 0,
      y: -70,
    },
    to: {
      opacity: 1,
      y: 0,
    },
    ease: 'CubicBezier',
    duration: 0.8,
    delay: 0,
  },

  'slide-left': {
    from: {
      opacity: 0,
      x: 70,
    },
    to: {
      opacity: 1,
      x: 0,
    },
    ease: 'CubicBezier',
    duration: 0.8,
    delay: 0,
  },

  'slide-right': {
    from: {
      opacity: 0,
      x: -70,
    },
    to: {
      opacity: 1,
      x: 0,
    },
    ease: 'CubicBezier',
    duration: 0.8,
    delay: 0,
  },

  'zoom-in': {
    from: {
      scale: 0.9,
      opacity: 0,
      filter: filterBlur(),
    },
    to: {
      scale: 1,
      opacity: 1,
      filter: 'blur(0px)',
    },
    delay: 0,
    ease: 'CubicBezier',
    duration: 0.8,
  },

  'zoom-out': {
    from: {
      scale: 1.1,
      opacity: 1,
      filter: filterBlur(),
    },
    to: {
      scale: 1,
      opacity: 1,
      filter: 'blur(0px)',
    },
    delay: 0,
    ease: 'CubicBezier',
    duration: 0.8,
  },

  'zoom-out-slide-right': {
    from: {
      scale: 1.1,
      opacity: 1,
      x: -70,
      filter: filterBlur(),
    },
    to: {
      scale: 1,
      opacity: 1,
      x: 0,
      filter: 'blur(0px)',
    },
    delay: 0,
    ease: 'CubicBezier',
    duration: 0.8,
  },

  'zoom-out-slide-left': {
    from: {
      scale: 1.1,
      opacity: 1,
      x: 70,
      filter: filterBlur(),
    },
    to: {
      scale: 1,
      opacity: 1,
      x: 0,
      filter: 'blur(0px)',
    },
    delay: 0,
    ease: 'CubicBezier',
    duration: 0.8,
  },

  'blur-in': {
    from: {
      opacity: 0,
      filter: filterBlur(),
    },
    to: {
      opacity: 1,
      filter: 'blur(0px)',
    },
    delay: 0,
    ease: 'CubicBezier',
    duration: 0.8,
  },
};

if (utils.isRTL()) {
  Object.keys(zanimationEffects).forEach((key) => {
    if (zanimationEffects[key].from.x) {
      zanimationEffects[key].from.x = -zanimationEffects[key].from.x;
    }
  });
}


const zanimation =  (el, callback)=>{
  const Selector = {
    DATA_ZANIM_TIMELINE: '[data-zanim-timeline]',
    DATA_KEYS: "[data-zanim-xs], [data-zanim-sm], [data-zanim-md], [data-zanim-lg], [data-zanim-xl]",
  }
  const DATA_KEY = {
    DATA_ZANIM_TRIGGER: 'data-zanim-trigger',
  };
  
  /*-----------------------------------------------
  |   Get Controller
  -----------------------------------------------*/
  let controllerZanim;
  const currentBreakpointName = utils.getCurrentScreenBreakpoint().currentBreakpoint;
  const currentBreakpointVal = utils.getCurrentScreenBreakpoint().breakpointStartVal;
  const getController = (element) => {
    let options = {};
    let controller = {};
   
    if (element.hasAttribute(`data-zanim-${currentBreakpointName}`)) {
      controllerZanim = `zanim-${currentBreakpointName}`;
    }
    else {
      /*-----------------------------------------------
      |   Set the mobile first Animation
      -----------------------------------------------*/
      let animationBreakpoints = [];

      const attributes = element.getAttributeNames()
      attributes.forEach( attribute => {
        
        if( attribute !==DATA_KEY.DATA_ZANIM_TRIGGER && attribute.startsWith('data-zanim-')){
          const breakPointName = attribute.split('data-zanim-')[1];
          if (utils.breakpoints[breakPointName] < currentBreakpointVal) {
            animationBreakpoints.push({
              name: breakPointName,
              size: utils.breakpoints[breakPointName],
            });
          }
        }

      })

      controllerZanim = undefined;
      if (animationBreakpoints.length !== 0) {
        animationBreakpoints = animationBreakpoints.sort((a, b) => a.size - b.size);
        const activeBreakpoint = animationBreakpoints.pop();
        controllerZanim = `zanim-${activeBreakpoint.name}`;
      }

    }

    const userOptions = utils.getData(element, controllerZanim);
    controller = window._.merge( options, userOptions )

    if (!(controllerZanim === undefined)) {
      if (userOptions.animation) {
        options = zanimationEffects[userOptions.animation];
      } else {
        options = zanimationEffects.default;
      }
    }
    if (controllerZanim === undefined) {
      options = {
        delay: 0,
        duration: 0,
        ease: 'Expo.easeOut',
        from: {},
        to: {},
      };
    }

    /*-----------------------------------------------
    |   populating the controller
    -----------------------------------------------*/
    controller.delay || (controller.delay = options.delay);
    controller.duration || (controller.duration = options.duration);
    controller.from || (controller.from = options.from);
    controller.to || (controller.to = options.to);

    if (controller.ease) {
      controller.to.ease = controller.ease;
    } else {
      controller.to.ease = options.ease;
    }  

    return controller;
  
  };
  /*-----------------------------------------------
  |   End of Get Controller
  -----------------------------------------------*/

  /*-----------------------------------------------
  |   For Timeline
  -----------------------------------------------*/

  const zanimTimeline = el.hasAttribute('data-zanim-timeline');
  if(zanimTimeline){
    const timelineOption = utils.getData(el, 'zanim-timeline');     
    const timeline = gsap.timeline(timelineOption)
    
    const timelineElements =el.querySelectorAll(Selector.DATA_KEYS)
    timelineElements.forEach((timelineEl) => {
      const controller = getController(timelineEl);
      timeline
        .fromTo(
          timelineEl,
          controller.duration,
          controller.from,
          controller.to,
          controller.delay
        )
      .pause();
      window.imagesLoaded( timelineEl, callback(timeline));

    })      
  }
  else if (!el.closest(Selector.DATA_ZANIM_TIMELINE)){
    /*-----------------------------------------------
    |   For single elements outside timeline
    -----------------------------------------------*/
    const controller = getController(el);  
    callback(
      gsap
        .fromTo(el, controller.duration, controller.from, controller.to)
        .delay(controller.delay)
        .pause()
    );
  }

  callback(gsap.timeline());

}

/*-----------------------------------------------
|    Zanimation Init
-----------------------------------------------*/

const zanimationInit = ( ()=>{
  const Selector = {
    DATA_ZANIM_TRIGGER: '[data-zanim-trigger]',
    DATA_ZANIM_REPEAT: '[zanim-repeat]',
  };
  const DATA_KEY = {
    DATA_ZANIM_TRIGGER: 'data-zanim-trigger',
  };

  const Events = {
    SCROLL: 'scroll',
  };

  /*-----------------------------------------------
  |   Triggering zanimation when the element enters in the view
  -----------------------------------------------*/
  const triggerZanimation =  () => {
    const triggerElement = document.querySelectorAll(Selector.DATA_ZANIM_TRIGGER);
    triggerElement.forEach( el =>{
      if( utils.isElementIntoView(el) && el.hasAttribute(DATA_KEY.DATA_ZANIM_TRIGGER) ){   
        zanimation( el, animation => animation.play());
        if(!document.querySelector(Selector.DATA_ZANIM_REPEAT)){
          el.removeAttribute(DATA_KEY.DATA_ZANIM_TRIGGER)
        }
      }
    });
  };

  triggerZanimation();
  window.addEventListener(Events.SCROLL, () => triggerZanimation() );

})


const gsapAnimation = {
  zanimationInit,
  zanimation
};
export default gsapAnimation;