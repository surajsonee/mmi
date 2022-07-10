import utils from './utils';
/*-----------------------------------------------
|   Fancynav
-----------------------------------------------*/
const fancyNavInit = () => {
  const ClassName = {
    SHOW: 'show',
    PLAY: 'play',
    COLLAPSED: 'collapsed',
    FANCYNAVBAR_LEFT: 'fancynavbar-left',
    FANCYNAVBAR_TOP: 'fancynavbar-top'
  };
  const Selector = {
    FANCYNAVBAR: '.fancynavbar',
    FANCYNAVBAR_LEFT: '.fancynavbar-left',
    FANCYNAVBAR_TOGGLERBAR: '.fancynavbar-togglerbar',
    FANCYNAVBAR_BRAND_IMG: '.fancynavbar-brand-img',
    FANCYNAVBAR_ADDON: '.fancynavbar-addon',
    FANCYNAVBAR_COLLAPSE: '.fancynavbar-collapse',
    FANCYNAVBAR_TOGGLER: '.fancynavbar-toggler',
    FANCYNAVBAR_TOGGLER_ICON: '.fancynavbar-toggler-icon',
    PATH_TOP: '#path-top',
    PATH_MIDDLE: '#path-middle',
    PATH_BOTTOM: '#path-bottom',
    FANCYNAV_LINK: '.fancynav-link',
    FANCY_DROPDOWN: '.fancy-dropdown',
    FANCY_DROPDOWN_MENU: '.fancy-dropdown-menu',
    FANCY_DROPDOWN_TOGGLE: '.fancy-dropdown-toggle',
    FANCY_DROPDOWN_ITEM: '.fancy-dropdown-item',
    DATA_ONE_PAGE: '[data-one-page]'
  };
  const DATA_KEY = {
    ZANIM_XS: 'data-zanim-xs',
    ZANIM_MD: 'data-zanim-md',
    ZANIM_LG: 'data-zanim-lg',
    EXCLUSIVE: 'data-exclusive'
  };
  const Events = {
    CLICK: 'click',
    SCROLL: 'scroll',
    RESIZE: 'resize'
  };
  const EASE = 'CubicBezier';
  const fancynavbar = document.querySelector(Selector.FANCYNAVBAR);
  const isFancynavbarLeft = fancynavbar?.classList.contains(ClassName.FANCYNAVBAR_LEFT);
  const isFancynavbarTop = fancynavbar?.classList.contains(ClassName.FANCYNAVBAR_TOP);

  /*-----------------------------------------------
  |   RTL compatibility
  -----------------------------------------------*/
  if ((utils.isRTL() || isFancynavbarLeft) && !(utils.isRTL() && isFancynavbarLeft)) {
    const fancyNavbarBrandImg = document.querySelector(Selector.FANCYNAVBAR_BRAND_IMG);
    const fancyNavbarTogglerIcon = document.querySelector(Selector.FANCYNAVBAR_TOGGLER_ICON);
    const fancyNavbarAddon = document.querySelector(Selector.FANCYNAVBAR_ADDON);

    const reverseZanimData = el => {
      const attrObj = JSON.parse(el.getAttribute(DATA_KEY.ZANIM_LG));
      attrObj.from.x = -attrObj.from.x;
      const attrStr = JSON.stringify(attrObj);
      el.setAttribute(DATA_KEY.ZANIM_LG, attrStr);
    };
    reverseZanimData(fancynavbar);
    reverseZanimData(fancyNavbarBrandImg);
    reverseZanimData(fancyNavbarTogglerIcon);
    reverseZanimData(fancyNavbarAddon);
  }

  if (isFancynavbarTop) {
    const fancyNavbarBrandImg = document.querySelector(Selector.FANCYNAVBAR_BRAND_IMG);
    const fancyNavbarTogglerIcon = document.querySelector(Selector.FANCYNAVBAR_TOGGLER_ICON);
    const fancyNavbarAddon = document.querySelector(Selector.FANCYNAVBAR_ADDON);

    const setZanimData = (el, anim) => {
      const animStr = JSON.stringify(anim);
      el.setAttribute(DATA_KEY.ZANIM_LG, animStr);
    };
    const reverseZanimDataY = (el, val) => {
      const attrObj = JSON.parse(el.getAttribute(DATA_KEY.ZANIM_LG));
      attrObj.from.y = -val;
      const attrStr = JSON.stringify(attrObj);
      el.setAttribute(DATA_KEY.ZANIM_LG, attrStr);
    };
    const anim = JSON.parse(fancynavbar.getAttribute(DATA_KEY.ZANIM_XS));
    const childAnim = { ...anim, delay: 0.4 };
    const addonAnim = { ...anim, delay: 0.5 };

    setZanimData(fancynavbar, anim);
    setZanimData(fancyNavbarBrandImg, childAnim);
    reverseZanimDataY(fancyNavbarBrandImg, 38);

    setZanimData(fancyNavbarTogglerIcon, childAnim);
    setZanimData(fancyNavbarAddon, addonAnim);
    reverseZanimDataY(fancyNavbarAddon, 30);
  }

  if (fancynavbar) {
    const fancyNavbarCollapse = document.querySelector(Selector.FANCYNAVBAR_COLLAPSE);
    const fancyNavbarToggler = document.querySelector(Selector.FANCYNAVBAR_TOGGLER);
    const exclusive = document.querySelector(`[${DATA_KEY.EXCLUSIVE}]`);
    let x = '100%';
    (utils.isRTL() || isFancynavbarLeft) && !(utils.isRTL() && isFancynavbarLeft) && (x = '-100%');

    /*-----------------------------------------------
    |   Fancy Navbar Collapse Animation
    -----------------------------------------------*/
    const fancyNavbarCollapseTimeline = window.gsap.timeline().pause();
    const fancyNavItems = document.querySelectorAll(
      `${Selector.FANCYNAV_LINK}, ${Selector.FANCY_DROPDOWN_MENU}`
    );
    //$fancyNavItems.css('opacity', 0);

    fancyNavbarCollapseTimeline
      .fromTo(fancyNavbarCollapse, 0.6, { x }, { x: '0%', ease: EASE })
      .staggerFromTo(
        Array.from(fancyNavItems),
        0.8,
        { y: 56, opacity: 0 },
        { y: 0, opacity: 1, ease: EASE },
        0.05,
        '-=0.4'
      );
    /*-----------------------------------------------
    |   End of Drawer Animation
    -----------------------------------------------*/

    /*-----------------------------------------------
    |   Fancy Navbar Toggler Icon Animation
    -----------------------------------------------*/
    const fancyNavbarTogglerIconTimeline = window.gsap.timeline().pause();
    const fancyNavbarTogglerIcon = document.querySelector(Selector.FANCYNAVBAR_TOGGLER_ICON);
    const fancyNavbarTogglerIconPathTop = fancyNavbarTogglerIcon.querySelector(Selector.PATH_TOP);
    const fancyNavbarTogglerIconPathMiddle = fancyNavbarTogglerIcon.querySelector(
      Selector.PATH_MIDDLE
    );
    const fancyNavbarTogglerIconPathBottom = fancyNavbarTogglerIcon.querySelector(
      Selector.PATH_BOTTOM
    );

    fancyNavbarTogglerIconTimeline
      .fromTo(
        fancyNavbarTogglerIconPathTop,
        0.5,
        {
          'stroke-dashoffset': '0',
          'stroke-dasharray': '30px 88px'
        },
        {
          'stroke-dashoffset': '-81px',
          delay: 0,
          ease: EASE
        },
        0
      )
      .fromTo(
        fancyNavbarTogglerIconPathMiddle,
        0.5,
        {
          'stroke-dashoffset': '0',
          'stroke-dasharray': '30px 30px'
        },
        {
          'stroke-dashoffset': '-15px',
          'stroke-dasharray': '0.1px 30px',
          delay: 0,
          ease: EASE
        },
        0
      )
      .fromTo(
        fancyNavbarTogglerIconPathBottom,
        0.5,
        {
          'stroke-dashoffset': '-87.9px',
          'stroke-dasharray': '30px 88.1px'
        },
        {
          'stroke-dashoffset': '-6.3px',
          delay: 0,
          ease: EASE
        },
        0
      );
    /*-----------------------------------------------
    |   End of Fancy Navbar Toggler Icon Animation
    -----------------------------------------------*/

    const animateMenu = () => {
      fancyNavbarTogglerIcon.classList.contains(ClassName.PLAY)
        ? fancyNavbarTogglerIconTimeline.reverse()
        : fancyNavbarTogglerIconTimeline.play();
      fancyNavbarTogglerIcon.classList.toggle(ClassName.PLAY);

      fancyNavbarToggler.classList.contains(ClassName.COLLAPSED)
        ? fancyNavbarCollapseTimeline.reverse()
        : fancyNavbarCollapseTimeline.play();
      fancyNavbarToggler.classList.toggle(ClassName.COLLAPSED);
    };
    fancyNavbarToggler.addEventListener(Events.CLICK, animateMenu);

    document.querySelector('main').addEventListener(Events.CLICK, () => {
      fancyNavbarToggler.classList.contains(ClassName.COLLAPSED) && animateMenu();
    });

    /*-----------------------------------------------
    |   Resize Fancy Dropdown
    -----------------------------------------------*/
    const fancyDropdownMenus = document.querySelectorAll(Selector.FANCY_DROPDOWN_MENU);

    if (fancyDropdownMenus.length) {
      fancyDropdownMenus.forEach(el => {
        const fancyDropdownMenu = el;
        const dpMenuPrevSiblingHeight =
          fancyDropdownMenu.previousElementSibling.offsetHeight + 'px';
        fancyDropdownMenu.closest(Selector.FANCY_DROPDOWN).style.height = dpMenuPrevSiblingHeight;
      });

      /*-----------------------------------------------
      |   On Resize, Adjust the Menu Height
      -----------------------------------------------*/
      window.resize(() => {
        const fancyDropdownList = document.querySelectorAll(Selector.FANCY_DROPDOWN);
        fancyDropdownList.forEach(el => {
          const fancyDropdown = el;
          const dropdownToggleHeight = el.querySelector(
            Selector.FANCY_DROPDOWN_TOGGLE
          ).offsetHeight;

          if (fancyDropdown.classList.contains(ClassName.SHOW)) {
            const fancyDropdownMenuHeight = fancyDropdown.querySelector(
              Selector.FANCY_DROPDOWN_MENU
            ).offsetHeight;
            fancyDropdown.style.height = dropdownToggleHeight + fancyDropdownMenuHeight + 'px';
          } else {
            fancyDropdown.style.height = dropdownToggleHeight + 'px';
          }
        });
      });
    }
    /*-----------------------------------------------
    |   End of Resize Fancy Dropdown
    -----------------------------------------------*/
    const fancyNavLinks = document.querySelectorAll(Selector.FANCYNAV_LINK);
    fancyNavLinks.forEach(fancyNavLink => {
      fancyNavLink.addEventListener(Events.CLICK, e => {
        const fancyLink = e.target;
        // if one-page
        if (fancyLink.closest(Selector.DATA_ONE_PAGE)) {
          animateMenu();
        } else {
          const fancyDropdownMenuTl = window.gsap.timeline().pause();
          const targetFancyLink = fancyLink.closest(Selector.FANCY_DROPDOWN_TOGGLE);

          const targetNavSiblings = targetFancyLink?.nextElementSibling;
          const siblingsList = targetNavSiblings?.querySelectorAll(Selector.FANCY_DROPDOWN_ITEM);
          const listOfItems = Array.from(siblingsList);

          fancyDropdownMenuTl
            .staggerFromTo(
              listOfItems,
              0.3,
              { y: 30, opacity: 0 },
              { y: 0, opacity: 1, ease: EASE },
              0.01
            )
            .delay(0.1);

          const targetFancyLinkParentLi = fancyLink?.closest(Selector.FANCY_DROPDOWN);
          targetFancyLinkParentLi?.classList?.toggle(ClassName.SHOW);

          if (fancyLink.closest(Selector.FANCY_DROPDOWN).classList.contains(ClassName.SHOW)) {
            targetFancyLinkParentLi.style.height =
              targetFancyLink.offsetHeight + targetFancyLink.nextElementSibling.offsetHeight + 'px';
            fancyDropdownMenuTl.play();
          } else {
            fancyDropdownMenuTl.reverse();
            targetFancyLinkParentLi.style.height = targetFancyLink.offsetHeight + 'px';
          }

          /*-----------------------------------------------
        |   Exclusive
        -----------------------------------------------*/

          if (exclusive) {
            const currentDropdownEl = fancyLink.closest(Selector.FANCY_DROPDOWN);
            const dropdownElements = document.querySelectorAll(Selector.FANCY_DROPDOWN);
            dropdownElements.forEach(item => {
              const dropdownElement = item;
              if (dropdownElement !== currentDropdownEl) {
                dropdownElement.style.height = targetFancyLink.offsetHeight + 'px';
                dropdownElement.classList.remove(ClassName.SHOW);
              }
            });
          }
        }
      });
    }); //------------- click event end ------------

    /*-----------------------------------------------
    |   Transparency on scroll on mobile
    -----------------------------------------------*/
    const togglerbar = document.querySelector(Selector.FANCYNAVBAR_TOGGLERBAR);
    const onscrollFadeIn = utils.getData(togglerbar, 'onscroll-fade-in');
    const prevBgColor = window.getComputedStyle(togglerbar).backgroundColor;
    let prevBgClass = togglerbar.classList.value
      .split(' ')
      .filter(className => className.indexOf('bg-') === 0)[0];

    if (onscrollFadeIn) {
      let sideNavBgColor = window.getComputedStyle(togglerbar).backgroundColor;
      if (sideNavBgColor === 'transparent') sideNavBgColor = 'rgb(0, 0, 0)';
      if (sideNavBgColor.indexOf('a') === -1) {
        sideNavBgColor = sideNavBgColor.replace(')', ', 1)').replace('rgb', 'rgba');
      }
      let backgroundColorAlpha = sideNavBgColor.split(', ')[3].split(')')[0];
      if (window.pageYOffset === 0) backgroundColorAlpha = 0;

      const fancynavBreakpoint = fancynavbar.classList.value
        .split(' ')
        .filter(className => className.indexOf('fancynavbar-expand') === 0)[0]
        .split('fancynavbar-expand-')[1];

      const ChangeFancyNavBG = () => {
        const windowHeight = window.innerHeight;
        if (window.innerWidth > utils.breakpoints[fancynavBreakpoint]) {
          prevBgClass && togglerbar.classList.add(prevBgClass);
          togglerbar.style.backgroundColor =
            prevBgColor.replace('rgba', 'rgb').split(',').slice(0, 3).join() + ')';
        } else {
          togglerbar.classList.remove(prevBgClass);
          const tempBgColor = sideNavBgColor.split(', ');
          let bgColor = tempBgColor.join();
          togglerbar.style.backgroundColor = bgColor;
          const adjustFancyNavBG = () => {
            if (window.innerWidth < utils.breakpoints[fancynavBreakpoint]) {
              const scrollTop = window.pageYOffset;
              backgroundColorAlpha = (scrollTop / windowHeight) * 2;
              backgroundColorAlpha >= 1 && (backgroundColorAlpha = 1);
              tempBgColor[3] = `${backgroundColorAlpha})`;
              bgColor = tempBgColor.join();
              togglerbar.style.backgroundColor = bgColor;
            }
          };
          // adjustFancyNavBG();
          document.addEventListener(Events.SCROLL, () => adjustFancyNavBG());
        }
      };
      ChangeFancyNavBG();
      window.addEventListener(Events.RESIZE, () => ChangeFancyNavBG());
    }
  }
};

export default fancyNavInit;
